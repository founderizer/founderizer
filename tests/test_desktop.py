import base64
import copy
import json
import os
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import desktop
import hub
import usage
import worker_install
# not `from test_ui_api import OwnerAPI`: a test class among this module's names runs all its tests here again
import test_ui_api


def frame(ts):
    return dict(status="live", image=base64.b64encode(b"\xff\xd8\xffproof\xff\xd9").decode(), captured_at=ts)


class DesktopFrames(unittest.TestCase):
    def test_lease_expiry_stale_and_bounded_frames(self):
        frames = desktop.Frames(); key = ("db", 1, 1)
        self.assertFalse(frames.put(key, frame(10), 10))
        self.assertEqual(frames.view(key, 10)["status"], "waiting")
        self.assertTrue(frames.put(key, frame(11), 11))
        self.assertEqual(frames.view(key, 12)["status"], "live")
        for bad in [dict(frame(12), captured_at=1), dict(frame(12), captured_at=99),
                    dict(frame(12), image="not JPEG"), dict(frame(12), image="A" * 1500000),
                    dict(frame(12), extra="secret")]:
            with self.assertRaises(ValueError): frames.put(key, bad, 12)
        self.assertIsNone(frames.view(key, 17)["image"])
        frames.prune(26)
        self.assertEqual(frames.rows, {})

    def test_capture_never_starts_without_owner_lease(self):
        http = Mock(return_value=(409, {}))
        publisher = desktop.Publisher("studio", "T-1", {"attempt": 1, "generation": "db"}, http)
        with patch("desktop.subprocess.Popen") as start:
            publisher.run()
        start.assert_not_called()


class DesktopAPI(unittest.TestCase):
    setUp = test_ui_api.OwnerAPI.setUp
    tearDown = test_ui_api.OwnerAPI.tearDown
    connect = test_ui_api.OwnerAPI.connect
    request = test_ui_api.OwnerAPI.request

    def prepare(self):
        hub.DESKTOP = desktop.Frames()
        hub.TEAM["addresses"]["studio"] = "127.0.0.1"
        hub.TEAM["agents"]["studio"] = dict(role="worker", runtime="claude", machine="studio", can=["screen"])
        tid = hub.ins("INSERT INTO tasks(title,owner,state,needs,attempt) VALUES('Watch','studio','working','screen',1)")
        return tid, dict(generation="test-generation", attempt=1)

    def test_owner_lease_worker_fence_and_task_end(self):
        tid, context = self.prepare()
        view = f"/ui/tasks/{tid}/desktop?db=test-generation&attempt=1"
        post = f"/helper/desktop/studio/T-{tid}"
        self.assertEqual(self.request(view)[1]["status"], "waiting")
        self.assertEqual(self.request(post, dict(context, frame=frame(time.time())))[0], 200)
        self.assertEqual(self.request(view)[1]["status"], "live")
        self.assertEqual(self.request(post, dict(context, attempt=2, frame=frame(time.time())))[0], 409)
        self.assertEqual(self.request(view.replace("test-generation", "wrong"))[0], 409)
        self.assertEqual(self.request(view, headers={"Origin": "https://outside.example"})[0], 403)
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (tid,))
        self.assertEqual(self.request(view)[0], 409)
        self.assertEqual(hub.DESKTOP.rows, {})
        self.assertEqual(self.request(post, dict(context, frame=frame(time.time())))[0], 409)

    def test_wrong_host_no_address_and_hold_refuse_capture(self):
        tid, context = self.prepare()
        post = f"/helper/desktop/studio/T-{tid}"
        hub.TEAM["addresses"]["studio"] = "127.0.0.2"
        self.assertEqual(self.request(post, dict(context, frame=frame(time.time())))[0], 403)
        hub.TEAM["addresses"]["studio"] = ""
        self.assertEqual(self.request(post, dict(context, frame=frame(time.time())))[0], 403)
        hub.TEAM["addresses"]["studio"] = "127.0.0.1"
        hub.ins("INSERT INTO holds(task,kind,by,note,state,created,attempt) VALUES(?,'pause','owner','test','requested',?,1)", (tid,time.time()))
        self.assertEqual(self.request(post, dict(context, frame=frame(time.time())))[0], 409)
        self.assertEqual(self.request(f"/worker/install/studio")[1]["active_tasks"], [tid])


class ScreenUsage(unittest.TestCase):
    def test_cumulative_events_persist_once_with_workspace_agent_isolation(self):
        with tempfile.TemporaryDirectory() as home:
            # the screen records of a helper from before the threads' models: they are read and written as they are
            os.makedirs(os.path.join(home, '.fleet'))
            with sqlite3.connect(os.path.join(home, '.fleet/screen-usage.sqlite3')) as old:
                old.execute("CREATE TABLE sessions(kit TEXT, agent TEXT, thread TEXT, raw_input INTEGER, output INTEGER, cache_read INTEGER, since REAL, updated REAL, cache_write INTEGER DEFAULT 0, PRIMARY KEY(kit,agent,thread))")
            def event(i, o, c): return {"total": dict(inputTokens=i, outputTokens=o, cachedInputTokens=c,totalTokens=i+o)}
            # the runner names the thread's model from its start; an event without it keeps the one known
            for at, value in enumerate([event(100,10,80),event(200,20,150),event(200,20,150),event(100,10,80)]):
                usage.record_screen_usage('/kit','studio','thread-1',value,home,model='gpt-6-luna' if at == 1 else None)
            usage.record_screen_usage('/kit','other','thread-2',event(99,99,0),home)
            usage.record_screen_usage('/other','studio','thread-3',event(99,99,0),home)
            tokens = usage.screen_tokens('/kit','studio',home)
            self.assertEqual([tokens[k] for k in ('input','output','cache_read','total','sessions')], [50,20,150,220,1])
            self.assertEqual(usage.validate_usage(dict(tokens=tokens,limits=None), 'codex',screen=True)['tokens'],tokens)
            # each thread is a session of its own for the hub, with its four kinds (the lane "Tokens by day and model")
            self.assertEqual([(r['session_id'], r['input'], r['cache_read'], r['output'], r['calls'], r['model'])
                              for r in tokens['by_session']], [('thread-1', 50, 150, 20, 0, 'gpt-6-luna')])
            self.assertIsNone(usage.screen_tokens('/kit','new',home))
            usage.record_screen_usage('/kit','studio','thread-4',{'total':dict(inputTokens=10,outputTokens=1,cachedInputTokens=2,cacheWriteInputTokens=3,totalTokens=11)},home)
            self.assertEqual(usage.screen_tokens('/kit','studio',home)['cache_write'],3)
            with self.assertRaises(ValueError): usage.record_screen_usage('/kit','studio','t',event(10,1,11),home)
            # a thread whose counters went back (each column holds the most that it reported) has no input below 0, so
            # the reading still passes, with the agent's other sessions in it
            with sqlite3.connect(os.path.join(home, '.fleet/screen-usage.sqlite3')) as db:
                db.execute("UPDATE sessions SET raw_input=5, cache_read=4, cache_write=3 WHERE thread='thread-4'")
            tokens = usage.screen_tokens('/kit','studio',home)
            self.assertEqual(([r['input'] for r in tokens['by_session'] if r['session_id'] == 'thread-4'], tokens['input']),
                             ([0], 50))
            self.assertEqual(usage.validate_usage(dict(tokens=tokens,limits=None), 'codex',screen=True)['tokens'],tokens)
            # a runner that a release did not restart, and a release before this one, insert their nine values as they
            # did: the row stays, and the next write of a runner of this release gives it its model
            kit = str(usage.Path('/kit').resolve())
            with sqlite3.connect(os.path.join(home, '.fleet/screen-usage.sqlite3')) as db:
                db.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?,?)", (kit,'studio','thread-9',30,3,10,1.0,2.0,0))
            self.assertEqual([(r['input'], r['model']) for r in usage.screen_tokens('/kit','studio',home)['by_session']
                              if r['session_id'] == 'thread-9'], [(20, None)])
            usage.record_screen_usage('/kit','studio','thread-9',event(40,4,10),home,model='gpt-6-luna')
            self.assertEqual([(r['input'], r['model']) for r in usage.screen_tokens('/kit','studio',home)['by_session']
                              if r['session_id'] == 'thread-9'], [(30, 'gpt-6-luna')])

    def test_a_report_takes_the_newest_screen_threads_only(self):
        """A thread that grows is the newest, and a finished one does not change: SCREEN_BY_SESSION of them keep the
        report's room (REPORT_MAX) for the models of the agent's own sessions."""
        with tempfile.TemporaryDirectory() as home:
            event = {"total": dict(inputTokens=10, outputTokens=1, cachedInputTokens=0, totalTokens=11)}
            for at in range(usage.SCREEN_BY_SESSION + 1):
                usage.record_screen_usage('/kit','studio',f'thread-{at}',event,home)
            with sqlite3.connect(os.path.join(home, '.fleet/screen-usage.sqlite3')) as db:
                db.execute("UPDATE sessions SET updated=1000+CAST(substr(thread,8) AS INTEGER)")
            tokens = usage.screen_tokens('/kit','studio',home)
            names = [r['session_id'] for r in tokens['by_session']]
            self.assertEqual((len(names), names[0], 'thread-0' in names, tokens['sessions']),
                             (usage.SCREEN_BY_SESSION, f'thread-{usage.SCREEN_BY_SESSION}', False,
                              usage.SCREEN_BY_SESSION + 1))

    def test_mixed_usage_keeps_sources_separate(self):
        with tempfile.TemporaryDirectory() as home:
            usage.record_screen_usage('/kit','studio','thread-1',{"total":dict(inputTokens=100,outputTokens=10,cachedInputTokens=50,totalTokens=110)},home)
            data = dict(tokens=None,limits=None,screen=dict(tokens=usage.screen_tokens('/kit','studio',home),limits=None))
            self.assertEqual(usage.validate_usage(data,'claude'),data)
            bad=copy.deepcopy(data);bad['screen']['tokens']['source']='invented'
            with self.assertRaises(ValueError):usage.validate_usage(bad,'claude')
            bad=copy.deepcopy(data);bad['screen']['tokens']['secret']='not allowed'
            with self.assertRaises(ValueError):usage.validate_usage(bad,'claude')


class WorkerInstaller(unittest.TestCase):
    def test_unknown_identity_stops_before_service_mutation(self):
        with patch.object(worker_install.fleet,'TEAM',{'agents':{}}), patch('worker_install.run') as run:
            with self.assertRaises(ValueError):worker_install.check('new-worker')
            with self.assertRaises(ValueError):worker_install.check('../escape')
            run.assert_not_called()

    def test_service_names_are_scoped_to_agent_on_each_platform(self):
        with patch('worker_install.sys.platform','darwin'):
            self.assertEqual(worker_install.service_path('mini-2').name,'com.agentfleet.mini-2.plist')
        with patch('worker_install.sys.platform','linux'):
            self.assertEqual(worker_install.service_path('linux-2').name,'fleet-linux-2.service')
