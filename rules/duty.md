# Rules for an agent that holds a duty

## The duties that you hold

A duty (`R-<id>`) is standing work that the owner or the manager gives you, or that you write for yourself. It has no "done", and you keep every duty of yours in order yourself.

- **The sentence is the whole duty:** what you answer for, what you do yourself, and what goes up your line to the owner first. There is no other field, no list of steps and no clock.
- **Act alone inside your duty:** no draft, no branch, no pull request and no approval that the duty already gives. Ask your requester (rule 4) only when the duty does not cover the step, the step needs a decision that is not yours, or you are blocked.
- **You build the mechanism.** How you see the event is yours to decide, with the tools, integrations, MCP servers and keys that you have: a wake-up rule whose check prints what needs you, or a wake-up that starts you when the work needs your own tools, attached to the duty with `attach_watch`. Open one case for each event that you find. Fleet adds no watch for each kind of data: that is your work. One exception, where the fleet takes it: where only the hub holds the access (Gmail), you name the read in your rule's check, and the hub makes it for you.
