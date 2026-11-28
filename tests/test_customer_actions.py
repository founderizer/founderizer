"""The pure parts of a customer action (customer_actions.py; D143, customer-keyed-tools design v5): the form check that
keeps a support agent's fixed request to the customer's own record, the hub's own pattern matcher that a hostile value
meets under the hub's LOCK, and the hash that the owner's yes binds. Each test names the bug that it catches."""

import copy
import json
import random
import re
import unittest

import customer_actions as ca

REF = "bws://12345678-1234-1234-1234-123456789abc"
LOGIN = {"kind": "api_key", "site": "https://shop.example.com", "title": "Shop API key"}

# The design's three examples (design v5, 3), with the postcode at {3,6}
ORDER_STATUS = {
    "login": REF, "auth": "bearer", "headers": {"Accept": "application/json"},
    "read": {"method": "GET", "path": "/api/orders/{order}"},
    "fills": {"order": "^[0-9]{1,6}$", "postcode": "^[0-9A-Z]{3,6}$"},
    "owner": {"field": "customer.phone", "kind": "whatsapp_phone"},
    "also": {"field": "shipping.postcode", "fill": "postcode"},
    "returns": {"status": "^[a-z_]{1,19}$", "eta": "^[0-9-]{10}$"},
    "per_day": 5, "fleet_day": 200,
    "says": "The status of one of the customer's own orders, by its number and postcode."}
CANCEL_ORDER = {
    "login": REF, "auth": "bearer",
    "read": {"method": "GET", "path": "/api/orders/{order}"},
    "write": {"method": "POST", "path": "/api/orders/{order}/cancel", "body": {"reason": "{reason}"}},
    "fills": {"order": "^[0-9]{1,6}$", "postcode": "^[0-9A-Z]{3,6}$", "reason": "text:300"},
    "owner": {"field": "customer.phone", "kind": "whatsapp_phone"},
    "also": {"field": "shipping.postcode", "fill": "postcode"},
    "returns": {"state": "^[a-z_]{1,19}$"}, "per_day": 2, "fleet_day": 50,
    "says": "Cancel one of the customer's own orders."}
OPEN_TICKET = {
    "login": REF, "auth": "bearer",
    "write": {"method": "POST", "path": "/api/tickets",
              "body": {"requester_phone": "{phone}", "message": "{text}", "channel": "whatsapp"}},
    "fills": {"text": "text:1000"}, "binds": {"phone": "whatsapp_phone"},
    "owner": {"field": "requester_phone", "kind": "whatsapp_phone"},
    "returns": {"id": "^[0-9]{1,12}$", "state": "^[a-z_]{1,19}$"}, "per_day": 3, "fleet_day": 100,
    "says": "Open one ticket for this customer, with their words."}


def changed(action, **parts):
    """A deep copy of the action with fields replaced; a value None removes the field."""
    out = copy.deepcopy(action)
    for k, v in parts.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = v
    return out


class Form(unittest.TestCase):
    def refused(self, action, words, name="act", login=LOGIN):
        problem = ca.action_form(name, action, login)
        self.assertIsNotNone(problem, "the form passed an action that the design refuses")
        self.assertIn(words, problem)

    def test_the_designs_examples_pass(self):
        """A form check that refuses the design's own read, checked write and create leaves the owner nothing to
        give."""
        self.assertEqual(ca.agent_actions_form({"order_status": ORDER_STATUS, "cancel_order": CANCEL_ORDER,
                                                "open_ticket": OPEN_TICKET}, {REF: LOGIN}),
                         {"order_status": None, "cancel_order": None, "open_ticket": None})

    def test_a_create_with_a_pattern_fill_is_refused(self):
        """A create has no read that proves the record is the customer's, so a pattern fill in its path or body would
        write to any record whose number the customer guesses."""
        a = changed(OPEN_TICKET, write={"method": "POST", "path": "/api/orders/{order}/notes",
                                        "body": {"requester_phone": "{phone}", "message": "{text}"}},
                    fills={"text": "text:1000", "order": "^[0-9]{1,6}$"})
        self.refused(a, "a create")

    def test_a_partial_path_segment_is_refused(self):
        """`{order}9` lets a value end inside a segment that the read never checked."""
        self.refused(changed(ORDER_STATUS, read={"method": "GET", "path": "/api/orders/{order}9"}), "one whole")
        self.refused(changed(ORDER_STATUS, read={"method": "GET", "path": "/api/orders/x{order}"}), "one whole")
        self.refused(changed(ORDER_STATUS, read={"method": "GET", "path": "/api//orders/{order}"}), "never empty")
        self.refused(changed(ORDER_STATUS, read={"method": "GET", "path": "/api/../{order}"}), "never a .")

    def test_a_write_whose_fill_is_only_in_its_reads_query_is_refused(self):
        """A read that filters by a query value can answer with another record than the one that the write's path
        names; the write must act on the very record that the read's path fetched."""
        a = changed(CANCEL_ORDER, write={"method": "POST", "path": "/api/orders/{order}/items/{item}/cancel",
                                         "body": {"reason": "{reason}"}},
                    fills={"order": "^[0-9]{1,6}$", "postcode": "^[0-9A-Z]{3,6}$", "reason": "text:300",
                           "item": "^[0-9]{1,4}$"})
        self.refused(a, "must also be a whole part of its read's path")

    def test_a_write_whose_read_picks_its_record_by_query_or_by_no_name_is_refused(self):
        """The write repeats only the read's path: a read that picks the record by a query value, or a path such as
        /orders/latest, lets the write act on another customer's record than the one that the read checked."""
        fills = {"order": "^[0-9]{1,6}$", "postcode": "^[0-9A-Z]{3,6}$", "reason": "text:300"}
        for read, write, binds, used in (
                ("/api/orders/latest?customer={phone}", "/api/orders/latest/cancel", {"phone": "whatsapp_phone"},
                 ("postcode", "reason")),
                ("/api/orders/latest", "/api/orders/latest/cancel", {}, ("postcode", "reason")),
                ("/api/orders/{order}?view={phone}", "/api/orders/{order}/cancel", {"phone": "whatsapp_phone"},
                 ("order", "postcode", "reason"))):
            a = changed(CANCEL_ORDER, read={"method": "GET", "path": read},
                        write={"method": "POST", "path": write, "body": {"reason": "{reason}"}},
                        binds=binds or None, fills={k: fills[k] for k in used})
            self.refused(a, "by none in its query")

    def test_a_trailing_slash_passes(self):
        """Services that need a trailing / (Django REST) must not fail the form for a harmless fixed slash."""
        a = changed(CANCEL_ORDER, read={"method": "GET", "path": "/api/orders/{order}/"},
                    write={"method": "POST", "path": "/api/orders/{order}/cancel/", "body": {"reason": "{reason}"}})
        problem, parts = ca.action_parts("act", a, LOGIN)
        self.assertIsNone(problem)
        self.assertEqual((parts["read"]["segments"], parts["read"]["slash"]), (["api", "orders", "{order}"], True))
        self.assertEqual(parts["write"]["in_path"], ["order"])

    def test_a_write_outside_its_reads_path_is_refused(self):
        """A write to /api/users/{order} after a read of /api/orders/{order} acts on a record that nobody checked."""
        a = changed(CANCEL_ORDER, write={"method": "POST", "path": "/api/users/{order}/cancel",
                                         "body": {"reason": "{reason}"}})
        self.refused(a, "must start with its read's path")

    def test_a_write_whose_read_goes_through_a_list_is_refused(self):
        """An owner field in a list can match any one item of many, so a shared record would open a write."""
        self.refused(changed(CANCEL_ORDER, owner={"field": "contacts.0.phone", "kind": "whatsapp_phone"},
                             also={"field": "contacts.0.postcode", "fill": "postcode"}), "goes through no list")

    def test_a_write_with_no_also_is_refused(self):
        """A recycled order number alone would open a cancel of another customer's order after a change of number."""
        self.refused(changed(CANCEL_ORDER, also=None, fills={"order": "^[0-9]{1,6}$", "reason": "text:300"}),
                     "has also")

    def test_returns_and_also_through_another_list_index_are_refused(self):
        """A value of item 1 of a list whose item 0 holds the customer's phone is another person's value."""
        a = changed(ORDER_STATUS, owner={"field": "people.0.phone", "kind": "whatsapp_phone"},
                    returns={"people.1.status": "^[a-z_]{1,19}$"})
        self.refused(a, "goes into a list")
        self.refused(changed(ORDER_STATUS, owner={"field": "people.0.phone", "kind": "whatsapp_phone"},
                             also={"field": "people.1.postcode", "fill": "postcode"}), "goes into a list")
        for field in ("people.-1.status", "people.1_0.status", "people.01.status"):
            self.refused(changed(ORDER_STATUS, owner={"field": "people.0.phone", "kind": "whatsapp_phone"},
                                 returns={field: "^[a-z_]{1,19}$"}), "returns key")
        ok = changed(ORDER_STATUS, owner={"field": "people.0.phone", "kind": "whatsapp_phone"},
                     returns={"people.0.status": "^[a-z_]{1,19}$"})
        self.assertIsNone(ca.action_form("act", ok, LOGIN))

    def test_only_accept_and_version_headers(self):
        """Content-Type would let a write go as form fields that the service reads differently from the hub's JSON;
        any other header could carry a second credential or change the request."""
        for headers in ({"Content-Type": "application/x-www-form-urlencoded"}, {"X-Forwarded-Host": "x"},
                        {"Accept": "{order}"}, {"Authorization": "Bearer x"}):
            self.refused(changed(ORDER_STATUS, headers=headers), "header")
        self.assertIsNone(ca.action_form("act", changed(ORDER_STATUS, headers={"Stripe-Version": "2024-06-20"}),
                                         LOGIN))

    def test_a_header_name_comes_once_whatever_its_case(self):
        """Accept and accept are one header: a form that takes both lets the vault send two values of one header,
        and a service reads either one. Bug: the form compares header names with their case."""
        for headers in ({"Accept": "application/json", "accept": "text/html"},
                        {"Stripe-Version": "2024-06-20", "stripe-version": "2023-01-01"}):
            self.refused(changed(ORDER_STATUS, headers=headers), "two times")
        self.assertIsNone(ca.action_form("act", changed(ORDER_STATUS, headers={"Accept": "application/json",
                                                                               "Stripe-Version": "2024-06-20"}), LOGIN))

    def test_method_override_in_a_query_is_refused(self):
        """`_method=DELETE` turns a checked GET into a delete on many frameworks."""
        self.refused(changed(ORDER_STATUS, read={"method": "GET", "path": "/api/orders/{order}?_method=DELETE"}),
                     "_method")

    def test_a_read_is_a_get(self):
        """A read is sent before any check passes; a POST as a read would change the record before the check."""
        self.refused(changed(ORDER_STATUS, read={"method": "POST", "path": "/api/orders/{order}"}), "GET")

    def test_a_fill_that_can_hold_an_address_is_refused(self):
        """A fill that can carry an email, a phone number or a web address can make the service write to somebody
        other than the customer."""
        for pattern in ("^[a-z@.]{3,40}$", "^[0-9]{1,12}$", "^\\+[0-9]{7,15}$", "^[a-z:/.]{1,60}$",
                        "^[a-z0-9]{1,20}\\.[a-z]{2,4}$", "^[0-9]{1,6}@lid$", "^\\+[0-9]{2} [0-9]{3} [0-9]{3} [0-9]{3}$",
                        "^[0-9]{3}-[0-9]{3}-[0-9]{4}$", "^\\([0-9]{3}\\) [0-9]{3}-[0-9]{4}$", "^[0-9]{9} $",
                        "^-[0-9]{13}$", "^[0-9]{3}/[0-9]{3}/[0-9]{3}$"):
            self.refused(changed(ORDER_STATUS, fills={"order": pattern, "postcode": "^[0-9A-Z]{3,6}$"}),
                         "a fill never carries an address")

    def test_an_email_fill_that_only_also_reads_passes(self):
        """A fill that only also compares with the answer is never sent, so "the order's number and its email", the
        most common look-up, must pass."""
        a = changed(ORDER_STATUS, fills={"order": "^[0-9]{1,6}$", "email": "^[a-z0-9.@_-]{3,80}$"},
                    also={"field": "customer.email", "fill": "email"})
        self.assertIsNone(ca.action_form("act", a, LOGIN))
        self.refused(changed(a, read={"method": "GET", "path": "/api/orders/{order}?lookup={email}"}),
                     "a fill never carries an address")

    def test_an_also_fill_of_one_value_is_refused(self):
        """An also that accepts only "A", or "A" and "B", is no second fact that the customer knows: the order number
        alone opens it."""
        self.assertIsNone(ca.action_form("act", changed(CANCEL_ORDER, fills={
            "order": "^[0-9]{1,6}$", "postcode": "^[0-9][A-Z]$", "reason": "text:300"}), LOGIN))
        for pattern in ("^A$", "^[AB]$", "^[0-9]{1,1}$", "^A[A]{0,9}[A]{0,9}$"):
            self.refused(changed(CANCEL_ORDER, fills={"order": "^[0-9]{1,6}$", "postcode": pattern, "reason": "text:300"}),
                         "fewer than 100 values")

    def test_a_path_fill_never_accepts_dots_or_a_slash(self):
        """A path part "." or "..", or a value with / or \\ that a server decodes from %2F, moves the request to
        another path of the service."""
        self.refused(changed(ORDER_STATUS, fills={"order": "^[0-9.]{1,6}$", "postcode": "^[0-9A-Z]{3,6}$"}),
                     ". or ..")
        for pattern in ("^[./]{1,6}[a-z]{1,10}$", "^[0-9/]{1,6}$", "^[a-z\\\\]{1,6}$", "^[a-z%]{1,6}$", "^\\.\\.;[a-z]$"):
            self.refused(changed(ORDER_STATUS, fills={"order": pattern, "postcode": "^[0-9A-Z]{3,6}$"}),
                         "never holds")

    def test_an_address_word_never_leads_to_a_fill(self):
        """`{"to": "{order}"}` or `{"recipient": {"x": "{order}"}}` makes a fill the address of the service's mail."""
        for body in ({"to": "{order}", "reason": "{reason}"}, {"recipient": {"id": "{order}"}, "reason": "{reason}"},
                     {"replyEmail": "{order}", "reason": "{reason}"}, {"phone_number": "{order}", "reason": "{reason}"},
                     {"recipients": ["{order}"], "reason": "{reason}"}, {"e_mail": "{order}", "reason": "{reason}"},
                     {"to_list": "{order}", "reason": "{reason}"}, {"redirect_uri": "{order}", "reason": "{reason}"}):
            self.refused(changed(CANCEL_ORDER, write={"method": "POST", "path": "/api/orders/{order}/cancel",
                                                      "body": body}), "address")
        self.refused(changed(ORDER_STATUS, read={"method": "GET", "path": "/api/orders/{order}?notify_phone={postcode}"}),
                     "address word")
        self.assertFalse(ca.address_key("photo"))

    def test_a_fixed_address_in_a_body_is_refused(self):
        """A fixed recipient in a create sends the customer's words to a person who is not the customer."""
        for value in ("+34600000000", 34600000000):
            self.refused(changed(OPEN_TICKET, write={"method": "POST", "path": "/api/tickets",
                                                     "body": {"requester_phone": "{phone}", "message": "{text}",
                                                              "cc": value}}), "never a fixed address")
        ok = changed(OPEN_TICKET, write={"method": "POST", "path": "/api/tickets",
                                         "body": {"requester_phone": "{phone}", "message": "{text}", "notify_email": False}})
        self.assertIsNone(ca.action_form("act", ok, LOGIN))

    def test_a_fixed_address_anywhere_is_refused(self):
        """A fixed address under a key that the list misses, or in a query, sends the customer's words in the
        company's name to a fixed person."""
        msg = {"message": "{text}", "requester_phone": "{phone}"}
        for extra in ({"phonenumber": "+34600000000"}, {"emailaddress": "ops@example.com"},
                      {"chat_id": "-1001234567890"}, {"destination": "ops@example.com"}, {"telephone": "600123456"},
                      {"webhook": "https://evil.example.com/x"}, {"note_for": "ops@example.com"},
                      {"group": "+34 600 123 456"}):
            self.refused(changed(OPEN_TICKET, write={"method": "POST", "path": "/api/tickets", "body": dict(msg, **extra)}),
                         "address")
        self.refused(changed(OPEN_TICKET, write={"method": "POST", "path": "/api/sms?to=34600000000",
                                                 "body": msg}), "only a bind")
        self.refused(changed(OPEN_TICKET, write={"method": "POST", "path": "/api/sms?notify_phone=34600000000",
                                                 "body": msg}), "only a bind")
        self.refused(changed(OPEN_TICKET, write={"method": "POST", "path": "/api/sms?to=ops", "body": msg}), "only a bind")
        for flag in ("send_email=false", "with_phone=1"):
            self.assertIsNone(ca.action_form("act", changed(OPEN_TICKET, write={
                "method": "POST", "path": "/api/tickets?" + flag, "body": msg}), LOGIN), flag)
        for extra in ({"phone": "55555"}, {"tel": "112"}, {"phone": "800FLOWERS"}, {"url": "localhost:8080"},
                      {"telephone": "６００１２３４５６"}, {"contact": "ops＠example．com"}, {"sms": "+34600000000"},
                      {"phone_number": "T600123456"}, {"phone_number": 600123456}, {"sms": "600123456"}, {"fax": "600123"},
                      {"cell": "600123"}, {"email": "support"}, {"return_url": "localhost"},
                      {"contact": "ops@пример.рф"}, {"note_for": "пример.рф"}, {"sms_text": "55555"},
                      {"phone_text": "600 123 456"}, {"telephone": "support"}, {"target": "+٣٤٦٠٠١٢٣٤٥٦"}):
            self.refused(changed(OPEN_TICKET, write={"method": "POST", "path": "/api/tickets", "body": dict(msg, **extra)}),
                         "address")
        ok = changed(OPEN_TICKET, write={"method": "POST", "path": "/api/tickets?notify_phone={phone}",
                                         "body": dict(msg, group_id="100123456789", channel="whatsapp",
                                                      email_template="cancel_v2", notify_email="off",
                                                      email_subject="Your order was cancelled.",
                                                      phone_type="mobile")})
        self.assertIsNone(ca.action_form("act", ok, LOGIN))
        self.refused(changed(OPEN_TICKET, write={"method": "POST", "path": "/api/tickets",
                                                 "body": dict(msg, recipient_name="ops")}), "never a fixed address")

    def test_the_parsed_form_sends_only_its_names_and_copies_the_body(self):
        """The run sends only the names of `sent` (never an also fill that no probe checked), and fills a copy, so the
        next customer's request never carries the last one's words."""
        a = changed(ORDER_STATUS, fills={"order": "^[0-9]{1,6}$", "email": "^[a-z0-9.@_-]{3,80}$"},
                    also={"field": "customer.email", "fill": "email"})
        self.assertEqual(ca.action_parts("act", a, LOGIN)[1]["sent"], {"order"})
        parts = ca.action_parts("cancel_order", CANCEL_ORDER, LOGIN)[1]
        parts["write"]["body"]["reason"] = "changed"
        self.assertEqual(CANCEL_ORDER["write"]["body"], {"reason": "{reason}"})

    def test_method_override_in_a_body_is_refused(self):
        """Laravel reads `_method` from a JSON body: the service runs a DELETE while the owner's card says POST."""
        self.refused(changed(CANCEL_ORDER, write={"method": "POST", "path": "/api/orders/{order}/cancel",
                                                  "body": {"reason": "{reason}", "_method": "DELETE"}}), "_method")

    def test_a_text_fill_goes_only_into_a_message_key(self):
        """A customer's free words in a path, a query or an id key choose the record or the address."""
        self.refused(changed(CANCEL_ORDER, write={"method": "POST", "path": "/api/orders/{order}/cancel",
                                                  "body": {"order_id": "{reason}"}}), "Text fill")
        self.refused(changed(CANCEL_ORDER, write={"method": "POST", "path": "/api/orders/{order}/{reason}"}),
                     "Text fill")
        self.refused(changed(CANCEL_ORDER, write={"method": "POST", "path": "/api/orders/{order}/cancel",
                                                  "body": {"reason": ["{reason}"]}}), "Text fill")

    def test_a_partial_body_template_is_refused(self):
        """`"Order {order}"` mixes a value into fixed text, where the hub's one-pass replace no longer holds."""
        self.refused(changed(CANCEL_ORDER, write={"method": "POST", "path": "/api/orders/{order}/cancel",
                                                  "body": {"reason": "{reason}", "note": "Order {order}"}}),
                     "one whole")

    def test_a_returns_pattern_that_takes_a_sentence_is_refused(self):
        """Free words in a service's answer can carry a stranger's message or another customer's data back."""
        for pattern in ("^[a-z_]{1,40}$", "^[A-Za-z ]{1,200}$", "^[A-Za-z]{1,200}$", "^[a-z.]{1,200}$",
                        "^[a-z0-9]{1,200}$"):
            self.refused(changed(ORDER_STATUS, returns={"note": pattern}), "20 letters or more")

    def test_a_login_with_no_site_is_refused(self):
        """The site is what the owner's card shows and what the yes binds; with none, the owner gives a key with no
        place."""
        self.refused(ORDER_STATUS, "needs its site", login={"kind": "api_key", "title": "Shop API key"})
        self.refused(ORDER_STATUS, "needs its site", login={"kind": "api_key", "site": "http://shop.example.com"})
        self.refused(ORDER_STATUS, "not in the team's logins", login=None)

    def test_fields_that_only_the_hub_writes_are_refused(self):
        """An action that carries `active`, `hash` or `by` could claim the owner's yes."""
        for field in ("active", "hash", "by"):
            self.refused(changed(ORDER_STATUS, **{field: True}), "does not take")

    def test_a_name_that_is_a_fill_and_a_bind_is_refused(self):
        """A customer's fill under a bind's name would replace the handle that the chat app gave."""
        self.refused(changed(OPEN_TICKET, fills={"text": "text:1000", "phone": "text:20"}), "a fill and a bind")

    def test_auth_header_and_creates_bind_and_empty_fill(self):
        """auth header:Content-Type sends the key as the body's type; a create with no bind of the owner's kind can
        write a record that the hub cannot tie to the customer; an empty fill makes a path part empty."""
        self.refused(changed(ORDER_STATUS, auth="header:Content-Type"), "auth")
        self.assertIsNone(ca.action_form("act", changed(ORDER_STATUS, auth="header:X-Api-Key"), LOGIN))
        self.refused(changed(OPEN_TICKET, binds={"phone": "telegram_id"}), "binds the kind")
        self.refused(changed(ORDER_STATUS, fills={"order": "^[0-9]{0,6}$", "postcode": "^[0-9A-Z]{3,6}$"}),
                     "accepts an empty value")

    def test_bounds(self):
        """The counts keep probes from using up the real customers' room; a ninth action is past the card's room."""
        self.refused(changed(ORDER_STATUS, per_day=21), "per_day")
        self.refused(changed(ORDER_STATUS, fleet_day=True), "fleet_day")
        self.refused(changed(ORDER_STATUS, says="x" * 161), "says")
        many = {f"a{i}": ORDER_STATUS for i in range(9)}
        got = ca.agent_actions_form(many, {REF: LOGIN})
        self.assertEqual(sum(v is None for v in got.values()), 8)
        self.assertIn("at most 8", got["a8"])

    def test_auth_forms_are_call_apis(self):
        """A copy of call_api's auth rule that drifts from the hub's would let an action send its key in a header
        that call_api refuses, such as Content-Type."""
        import hub
        self.assertEqual(ca.AUTH_HEADER.pattern, hub.API_HEADER.pattern)
        self.assertEqual(ca.AUTH_FIXED, hub.API_AUTH_FIXED)


class Patterns(unittest.TestCase):
    def test_only_the_subset_parses(self):
        """A group, alternation, `.`, `*`, `+`, `?`, a shorthand class, a negated class, a back-reference or a
        look-around takes the matcher outside its linear bound or past what the form check can read."""
        for p in ("^(ab)$", "^a|b$", "^.{1,5}$", "^a*$", "^a+$", "^a?$", "^\\d{1,5}$", "^[^@]{1,9}$", "^(a)\\1$",
                  "^(?=a)a$", "^a{0}$", "^a{3,2}$", "^a{1,201}$", "^[a-]]$", "^[[:digit:]]$", "abc", "^abc",
                  "^[!--]$", "^[+--.]$", "^[a-z-0]$",
                  "^a$b$", "^é$", "^[z-a]$", "^" + "a" * 17 + "$"):
            with self.assertRaises(ca.PatternError, msg=p):
                ca.parse_pattern(p)

    def test_the_matcher_agrees_with_a_regex_engine(self):
        """A matcher that accepts a value its pattern refuses lets a hostile value through the fill check or into
        what reaches the customer. Python's re checks the hub's matcher here, on patterns of the subset only."""
        rng = random.Random(143)
        atoms = ["a", "b", "-", "\\.", "[ab]", "[a-c]", "[0-9]", "[a-z_-]", "[ab.]"]
        for _ in range(3000):
            pattern = "^" + "".join(rng.choice(atoms) + rng.choice(["", "{2}", "{0,2}", "{1,3}", "{0,1}"])
                                    for _ in range(rng.randint(1, 5))) + "$"
            elements = ca.parse_pattern(pattern)
            for _ in range(5):
                value = "".join(rng.choice("ab-.c0_9z") for _ in range(rng.randint(0, 9)))
                self.assertEqual(ca.pattern_match(elements, value), re.fullmatch(pattern[1:-1], value) is not None,
                                 (pattern, value))

    def test_a_hostile_value_costs_elements_times_its_length(self):
        """A pattern of 16 counted classes that overlap matches a hostile value of 500 characters with at most
        16 x 500 reads of its characters, so no customer's value holds the hub's LOCK for long; a value over 500
        characters is refused before any read."""
        class Counting(str):
            reads = 0

            def __getitem__(self, i):
                Counting.reads += 1
                return str.__getitem__(self, i)

        elements = ca.parse_pattern("^" + "[a-z0-9]{0,200}" * 15 + "[0-9]{1,200}$")
        for value, match in (("a" * 499 + "!", False), ("a" * 499 + "1", True), ("a" * 501, False)):
            Counting.reads = 0
            self.assertEqual(ca.pattern_match(elements, Counting(value)), match)
            self.assertLessEqual(Counting.reads, 16 * 500)

    def test_pattern_ok_checks_the_length_first(self):
        """A value over its bound is refused before any match, so the bound holds for every pattern."""
        self.assertFalse(ca.pattern_ok("^[a-z]{1,200}[a-z]{1,200}$", "a" * 201, ca.FILL_MOST))
        self.assertTrue(ca.pattern_ok("^[a-z]{1,200}[a-z]{1,200}$", "a" * 200, ca.FILL_MOST))
        self.assertTrue(ca.fill_ok("text:300", "Please cancel it."))
        self.assertFalse(ca.fill_ok("text:3", "Please"))
        self.assertFalse(ca.pattern_ok("^(a)$", "a", ca.FILL_MOST))

    def test_plain_words_of_the_card(self):
        """The owner's card says each pattern in plain words; wrong words make the owner give more than he reads."""
        self.assertEqual(ca.pattern_words("^[0-9]{1,6}$"), "1 to 6 digits")
        self.assertEqual(ca.pattern_words("^[0-9A-Z]{3,6}$"), "3 to 6 characters, each a capital letter or digit")
        self.assertEqual(ca.pattern_words("^[a-z_]{1,19}$"), "1 to 19 characters, each a small letter or _")
        self.assertEqual(ca.pattern_words("^[0-9-]{10}$"), "10 characters, each a digit or -")
        self.assertEqual(ca.pattern_words("text:300"), "their own words, at most 300 characters")
        self.assertEqual(ca.pattern_words("^A-[0-9]{2,4}$"), '"A", then "-", then 2 to 4 digits')
        self.assertEqual(ca.pattern_words("^[a,b]{2}$"), '2 characters, each a ",", "a" or "b"')
        self.assertEqual(ca.pattern_words("^[a-f]{4}$"), '4 characters from "a" to "f"')
        self.assertEqual(ca.pattern_words("^[!-/]$"), '1 character from "!" to "/"')
        self.assertEqual(ca.pattern_words('^["]{2}$'), "double quotation mark 2 times")


class Hash(unittest.TestCase):
    def test_every_field_and_the_logins_site_change_the_hash(self):
        """The owner's yes binds one hash: a field, or the login's site, kind, form or title, that the hash leaves out
        could change after the yes and keep the action active."""
        base = ca.action_hash("cancel_order", CANCEL_ORDER, LOGIN)
        self.assertEqual(base, ca.action_hash("cancel_order", copy.deepcopy(CANCEL_ORDER), dict(LOGIN)))
        seen = {base}
        for field in CANCEL_ORDER:
            a = copy.deepcopy(CANCEL_ORDER)
            a[field] = {"changed": field}
            seen.add(ca.action_hash("cancel_order", a, LOGIN))
        seen.add(ca.action_hash("cancel_order", changed(CANCEL_ORDER, headers={"Accept": "application/json"}), LOGIN))
        seen.add(ca.action_hash("cancel_order", CANCEL_ORDER, dict(LOGIN, site="https://other.example.com")))
        seen.add(ca.action_hash("cancel_order", CANCEL_ORDER, dict(LOGIN, form="header:x-api-key")))
        seen.add(ca.action_hash("cancel_other", CANCEL_ORDER, LOGIN))
        seen.add(ca.action_hash("cancel_order", CANCEL_ORDER, dict(LOGIN, title="Other key")))
        seen.add(ca.action_hash("cancel_order", CANCEL_ORDER, dict(LOGIN, kind="login")))
        self.assertEqual(len(seen), len(CANCEL_ORDER) + 7)
        self.assertEqual(ca.action_hash("o", changed(OPEN_TICKET, per_day=None), LOGIN),
                         ca.action_hash("o", changed(OPEN_TICKET, per_day=3), LOGIN))


PHONE = "+34600123456"
GOOD = {"customer": {"phone": "+34 600-123.456"}, "shipping": {"postcode": " ab 12 "}, "status": "shipped",
        "eta": "2026-11-30"}


def body(**changes):
    """The service's answer to the order_status read, as JSON text, with fields replaced."""
    return json.dumps(dict(copy.deepcopy(GOOD), **changes))


class Run(unittest.TestCase):
    """One run of an action (design v5, 3.2): the request, the check and the cut of the answer, and the runs of a
    customer's own words."""
    def parts(self, name, action):
        problem, parts = ca.action_parts(name, action, LOGIN)
        self.assertIsNone(problem)
        return parts

    def test_one_rule_reads_a_phone_number(self):
        """A rule that takes bare digits, a JSON number or digits of another script lets a service's number with no
        country, or of another customer, pass the owner check; a handle that is no full phone JID binds a hidden id or
        a group as the customer's number."""
        for value in ("+34 600 123 456", "0034-600.123.456", "(+34) 600123456", "+34\t600 123456", PHONE):
            self.assertEqual(ca.e164(value), PHONE, value)
        for value in ("34600123456", 34600123456, "", None, "+0034600123456", "+34 600 abc", "+34/600123456",
                      "+３４600123456", "+123456", "+1234567890123456", "00", "+", "++34600123456",
                      "0 0 34600123456x", "+34600123456" + " " * 600):
            self.assertIsNone(ca.e164(value), value)
        self.assertEqual(ca.whatsapp_e164("34600123456@s.whatsapp.net"), PHONE)
        for handle in ("34600123456@lid", "034600123456@s.whatsapp.net", "34600123456@s.whatsapp.net\n",
                       "120363012345678901@g.us", "+34600123456@s.whatsapp.net", "34600123456@s.whatsappXnet", None):
            self.assertIsNone(ca.whatsapp_e164(handle), handle)

    def test_the_request_carries_only_its_names_encoded_and_a_body_filled_once(self):
        """A path value with / or .. that the request does not encode reaches another path of the service; a fill that
        only also reads (it may be an email) goes to the service; a value that holds a {name} is filled again; and a
        run that fills the parsed body itself carries one customer's words into the next one's request."""
        status = self.parts("order_status", ORDER_STATUS)
        self.assertEqual(ca.action_request(status, "read", {"order": "123", "postcode": "AB12"}, {}),
                         ("GET", "/api/orders/123", None, {}))
        self.assertEqual(ca.action_request(status, "read", {"order": "a/b c?#%", "postcode": "AB12"}, {})[1],
                         "/api/orders/a%2Fb%20c%3F%23%25")
        for bad in (".", "..", "", "café", 7):
            with self.assertRaises(ca.ActionError, msg=bad):
                ca.action_request(status, "read", {"order": bad, "postcode": "AB12"}, {})
        with self.assertRaises(ca.ActionError):
            ca.action_request(status, "read", {"postcode": "AB12"}, {})        # no value of a name that it sends
        with self.assertRaises(ca.ActionError):
            ca.action_request(status, "write", {"order": "1"}, {})             # it has no write
        query = self.parts("q", changed(ORDER_STATUS, read={"method": "GET", "path": "/api/orders/?number={order}"}))
        self.assertEqual(ca.action_request(query, "read", {"order": "1 2", "postcode": "AB12"}, {})[1],
                         "/api/orders/?number=1%202")
        cancel = self.parts("cancel_order", CANCEL_ORDER)
        values = {"order": "123", "postcode": "AB12", "reason": "Please cancel {order}, \"now\"."}
        self.assertEqual(ca.action_request(cancel, "write", values, {}),
                         ("POST", "/api/orders/123/cancel", '{"reason":"Please cancel {order}, \\"now\\"."}',
                          {"Content-Type": "application/json"}))
        self.assertEqual(cancel["write"]["body"], {"reason": "{reason}"})
        self.assertEqual(ca.action_request(cancel, "read", values, {}), ("GET", "/api/orders/123", None, {}))
        ticket = self.parts("open_ticket", OPEN_TICKET)
        method, path, sent, headers = ca.action_request(ticket, "create", {"text": "Hola, café"}, {"phone": PHONE})
        self.assertEqual((method, path, json.loads(sent), headers),
                         ("POST", "/api/tickets", {"requester_phone": PHONE, "message": "Hola, café",
                                                   "channel": "whatsapp"}, {"Content-Type": "application/json"}))
        self.assertTrue(sent.isascii())
        with self.assertRaises(ca.ActionError):
            ca.action_request(ticket, "read", {"text": "x"}, {"phone": PHONE})   # a create is no read
        with self.assertRaises(ca.ActionError):
            ca.action_request(ticket, "create", {"text": 7}, {"phone": PHONE})   # a fill goes as a JSON string

    def test_a_fill_comes_only_from_the_values_and_a_bind_only_from_the_hub(self):
        """An address of the body is only the hub's own bind (design v5, 7). Bug: action_request takes a bind's
        value from the call's values (a ticket for another number), or a fill's value from the binds."""
        ticket = self.parts("open_ticket", OPEN_TICKET)
        with self.assertRaises(ca.ActionError):
            ca.action_request(ticket, "create", {"text": "Hello.", "phone": "+15550000000"}, {})
        sent = json.loads(ca.action_request(ticket, "create", {"text": "Hello.", "phone": "+15550000000"},
                                            {"phone": PHONE})[2])
        self.assertEqual(sent["requester_phone"], PHONE)
        status = self.parts("order_status", ORDER_STATUS)
        with self.assertRaises(ca.ActionError):
            ca.action_request(status, "read", {"postcode": "AB12"}, {"order": "123"})

    def test_a_read_passes_only_for_the_customers_own_record(self):
        """The owner check is the one fact that ties a record to the customer: another number, a number with no
        country, a JSON number, an also field that differs or is empty, a body that is not one JSON object, a key that
        comes two times (json.loads keeps the last one, another parser the first), or a digit part read as a key would
        each let another customer's record through."""
        parts = self.parts("order_status", ORDER_STATUS)

        def check(text, bound=PHONE, also="AB12", kind="whatsapp_phone"):
            return ca.check_answer(parts, "read", text, kind, bound, also)
        self.assertEqual(check(body()), (True, {"status": "shipped", "eta": "2026-11-30"}))
        for text, also in ((body(customer={"phone": "+34 699 999 999"}), "AB12"),
                           (body(customer={"phone": "34600123456"}), "AB12"),
                           (body(customer={"phone": 34600123456}), "AB12"), (body(customer=[PHONE]), "AB12"),
                           (body(), "AB13"), (body(shipping={"postcode": ""}), ""), (body(shipping={}), "AB12"),
                           ("[" + body() + "]", "AB12"), ("{", "AB12"), ("[" * 100000, "AB12"), (None, "AB12"),
                           (body() + body(), "AB12")):
            self.assertEqual(check(text, also=also), (False, {}), (text[:80] if text else text, also))
        self.assertEqual(check(body(), bound="+34699999999"), (False, {}))
        # two keys of one name: a reader of the first one sees another customer than a reader of the last one
        twice = '{"customer": {"phone": "+34699999999"}, ' + body()[1:]
        self.assertEqual(json.loads(twice)["customer"]["phone"], GOOD["customer"]["phone"])
        self.assertEqual(check(twice), (False, {}))
        self.assertEqual(check(body(shipping={"postcode": "AB12", "postcode ": "x"})), (True, {"status": "shipped",
                                                                                            "eta": "2026-11-30"}))
        self.assertEqual(check(body(), kind="telegram_id"), (False, {}))        # the kind is the action's own
        # a value that fails its pattern, a value too long, and true or false stay out; an integer is its digits
        self.assertEqual(check(body(status="Shipped, call Luis", eta=2026113000)), (True, {"eta": "2026113000"}))
        self.assertEqual(check(body(status="a" * 501, eta=True)), (True, {}))
        listed = self.parts("listed", changed(ORDER_STATUS, owner={"field": "contacts.0.phone", "kind": "whatsapp_phone"},
                                              returns={"contacts.0.state": "^[a-z]{1,9}$"}, also=None,
                                              fills={"order": "^[0-9]{1,6}$"}))
        good = {"contacts": [{"phone": PHONE, "state": "open"}]}
        self.assertEqual(ca.check_answer(listed, "read", json.dumps(good), "whatsapp_phone", PHONE, None),
                         (True, {"contacts.0.state": "open"}))
        keyed = {"contacts": {"0": {"phone": PHONE, "state": "open"}}}      # a digit part never reads a key
        self.assertEqual(ca.check_answer(listed, "read", json.dumps(keyed), "whatsapp_phone", PHONE, None),
                         (False, {}))

    def test_telegram_and_chat_ids_are_compared_as_text_and_never_as_a_phone(self):
        """A Telegram id or a chat id read as a phone number lets a service's phone field that holds the same digits
        pass for another customer."""
        tg = self.parts("tg", changed(ORDER_STATUS, owner={"field": "customer.tg", "kind": "telegram_id"}))
        for value, passed in (("123456789", True), (123456789, True), ("+123456789", False), (" 123456789", False),
                              (True, False)):
            got = ca.check_answer(tg, "read", body(customer={"tg": value}), "telegram_id", "123456789", "AB12")[0]
            self.assertEqual(got, passed, value)
        chat = self.parts("chat", changed(ORDER_STATUS, owner={"field": "customer.chat", "kind": "chat_id"}))
        self.assertTrue(ca.check_answer(chat, "read", body(customer={"chat": "discord:42"}), "chat_id", "discord:42",
                                        "AB12")[0])
        self.assertFalse(ca.check_answer(chat, "read", body(customer={"chat": "42"}), "chat_id", "discord:42",
                                         "AB12")[0])

    def test_a_write_gets_only_the_cut_and_the_read_of_a_write_keeps_nothing(self):
        """A write's answer is not about the owner (only the returns cut, design 3.2.8), and the read of a write
        only opens the write: a read of a write that kept its returns would carry a value to the customer's way back
        that no read action gave. A create's answer is checked against the bound handle."""
        cancel = self.parts("cancel_order", CANCEL_ORDER)
        self.assertEqual(ca.check_answer(cancel, "write", '{"state": "cancelled", "customer": {}}', "whatsapp_phone",
                                         None, None), (True, {"state": "cancelled"}))
        self.assertEqual(ca.check_answer(cancel, "write", "", "whatsapp_phone", None, None), (True, {}))
        self.assertEqual(ca.check_answer(cancel, "read", body(state="cancelled"), "whatsapp_phone", PHONE, "AB12"),
                         (True, {}))
        ticket = self.parts("open_ticket", OPEN_TICKET)
        answer = json.dumps({"requester_phone": "0034600123456", "id": 77, "state": "open"})
        self.assertEqual(ca.check_answer(ticket, "create", answer, "whatsapp_phone", PHONE, None),
                         (True, {"id": "77", "state": "open"}))
        self.assertEqual(ca.check_answer(ticket, "create", answer, "whatsapp_phone", "+34699999999", None), (False, {}))

    def test_a_value_that_shares_twelve_characters_with_a_customers_words_is_found(self):
        """A service that echoes the customer's own words (a ticket's subject) would bring free text back through a
        returns value; a fold that misses case, spaces, _, - or . lets the same words through in another form, and a
        hash with no salt of the hub's own can be read back from the stored hashes."""
        words = "Please mark it as Urgent Waiting-Customer, thanks."
        salt = "a" * 64
        known = ca.run_hashes(words, salt)
        self.assertTrue(known and all(len(h) == 32 for h in known))
        self.assertFalse(any("urgent" in h for h in known))
        for value, shared in (("urgent_waiting", True), ("URGENT.WAITING", True), ("urgentwaitin", True),
                              ("urgentwaiti", False), ("waiting_room", False), ("shipped", False)):
            self.assertEqual(ca.shares_run(value, salt, known), shared, value)
        self.assertFalse(ca.shares_run("urgent_waiting", "b" * 64, known))      # another hub's salt
        self.assertEqual(ca.run_hashes("short words", salt), set())
        self.assertEqual(ca.folded(" A_b-C.d\tE "), "abcde")


if __name__ == "__main__":
    unittest.main()
