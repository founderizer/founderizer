import base64
import copy
import json
import os
import sqlite3
import sys
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

    def test_a_capture_runs_and_its_frames_go_only_while_the_owner_s_view_asks(self):
        """The publisher starts its capture program (a whole command, as a Linux agent's screen-capture) only when the
        hub says that a view watches, posts the lines that the program prints, and stops the program when the view
        stops: all of its process group, so that a program which the capture started (ffmpeg on a screen that does
        not answer) does not stay behind. A capture that ran with no view would read the screen, and send it, while
        nobody looks. With `hub_clock` each frame's time goes on the hub's clock, which here is 100 seconds ahead and
        then 90 (a slow answer): the hub refuses a frame whose time is more than 2 seconds ahead of its own, or 5
        behind, or before the frame that it holds, so the second frame's time is never before the first one's. A
        Mac's frames keep their time. The view watches until two frames came, however long this machine takes."""
        program = ("import json, subprocess, sys, time\n"
                   "child = subprocess.Popen(['sleep', '60'])\n"
                   "for n in range(600):\n"
                   f"    print(json.dumps(dict({frame(5)!r}, captured_at=5 + n / 100, child=child.pid)), flush=True)\n"
                   "    time.sleep(0.1)\n")
        for hub_clock in (False, True):
            calls, ran, sent = [], [], []

            def http(method, path, data=None, timeout=None):
                ran.append(publisher.process is not None)       # whether the capture runs when this call starts
                calls.append(method)
                if method == "POST":
                    sent.append(data["frame"])
                    return 200, {}
                if len(calls) == 1:
                    return 200, {"watching": False}
                if len(sent) < 2:                               # the view watches until its second frame came
                    return 200, {"watching": True, "now": time.time() + (90 if sent else 100)}
                return (200, {"watching": False}) if calls[-2] == "POST" else (409, {})
            publisher = desktop.Publisher("studio", "T-1", {"attempt": 1, "generation": "db"}, http,
                                          command=[sys.executable, "-c", program], hub_clock=hub_clock)
            publisher.stop.wait = lambda seconds: None
            publisher.run()
            self.assertEqual((calls[:2], calls[-3:], len(sent)), (["GET", "GET"], ["POST", "GET", "GET"], 2))
            self.assertEqual((ran[:2], ran[-2:]), ([False, False], [True, False]))
            self.assertEqual((publisher.process, publisher.ended), (None, 409))
            child = sent[0].pop("child")
            times = [f.pop("captured_at") for f in sent]
            self.assertEqual(sent[0], {k: v for k, v in frame(5).items() if k != "captured_at"})
            if hub_clock:
                self.assertTrue(104 < times[0] < 112, times)
                self.assertEqual(times[1], times[0])            # 10 seconds less ahead: not before the first one
            else:
                self.assertTrue(5 <= times[0] < times[1] < 12, times)
            for _ in range(50):                 # the child of the capture went with its group
                try:
                    os.kill(child, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.1)
            else:
                os.kill(child, 9)
                self.fail("a program that the capture started stayed behind")

    def test_a_jump_of_a_clock_does_not_hold_the_frames_times_ahead(self):
        """A frame's time on the hub's clock is never before the last one sent, and a time more than the hub's 2
        seconds after its clock comes back to 1 second after it. This machine's clock stepped 1,000 seconds forward
        between the hub's answer and a frame: that frame's time is too new, and without the limit every later frame
        kept that time, which the hub refuses for the 1,000 seconds."""
        sent, times = [], iter([time.time() + 1000, time.time(), time.time()])
        answers = iter([(200, {"watching": True, "now": time.time()})] * 2 + [(409, {})])

        def http(method, path, data=None, timeout=None):
            if method == "POST":
                sent.append(data["frame"]["captured_at"])
                return 200, {}
            return next(answers)
        publisher = desktop.Publisher("box", "T-1", {"attempt": 1, "generation": "db"}, http, hub_clock=True)
        publisher.frame = lambda: frame(next(times))
        publisher.stop.wait = lambda seconds: None
        publisher.run()
        self.assertEqual(len(sent), 2)
        self.assertLessEqual(sent[0], sent[1])
        self.assertLess(sent[1], time.time() + 2)

    def test_a_capture_that_does_not_end_never_stops_the_publisher_s_close(self):
        """close_capture gives the capture two signals and two short waits, and then lets it go: a wait that raised
        (a process that the kernel had not ended yet) left the publisher's thread with an error and its capture's
        pipe open."""
        publisher = desktop.Publisher("studio", "T-1", {"attempt": 1, "generation": "db"}, lambda *a, **kw: (409, {}))
        publisher.process = Mock(pid=2 ** 22 + 7)               # no such process group
        publisher.process.wait.side_effect = desktop.subprocess.TimeoutExpired("capture", 2)
        process = publisher.process
        publisher.close_capture()
        self.assertEqual((publisher.process, process.stdout.close.call_count), (None, 1))


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
