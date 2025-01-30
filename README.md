# build-control
Proof-of-concept and framework for pervasive computing

## Protocol:

- the controller is the server
when you want to control a build program, you pass
BUILDCONTROLADDR=socket-addr
BUILDTOKEN=unique-hash

The socket address can be a local path (unix domain)
or a servername[:service] to be resolved by getaddrinfo

- The build program connects to the server and passes
back the hash to identify itself

- whenever the controller wants to change the number of jobs,
it passes back the desired number of jobs.

- text-based protocol, so follows the age-old telnet classics where it
matters, namely passes \r\n for end of line, and will be happy with
any line termination on the receiving side (be it \n, \r\n, or even \r)

## Why this complexity:

- we want to be able to control every build on a cluster for a program
like dpb(1), so the address may need to be tcp.

- the hash offers security (unknown hash -> bye bye)

- some build programs, like make, will fork and exist in multiple instances.
Having the exact same build token means that the server will tell each client
for a given hash at the same time.

## Security vs simplicity

- maybe just passing BUILDCONTROLADDR should be enough ? when the
first client connects, he passes back the number of jobs and requests an ID.
The server logs that in, and further clients use the same hash for number
of jobs (appropriate for make).

- complex stuff like gmake with on-the-board allocation will require a bit
of work.  Now anything which manages its own jobs will require a bit of work.
Essentially, we often have a queue of free jobs, so when the job number
increases, we just need to allocate more free jobs and trigger job allocation.
When the job number decreases, we just need to mark finished jobs for garbage
collection. In all, if the number of jobs was implicit it needs to become
explicit.

- we will always exchange the current number of jobs, and not deltas,
because if we ever run over an unreliable medium (say udp), deltas would
be ill-advised. They're also way more vulnerable to any kind of attack.

## Optimization:

- the hash follows the pattern number-hash, where number is the project
number, just so you don't actually have to look-up a hash, the hash is
verified on connection as a basic security measure.
Note that it's just an optimisation based on the simple server.
The server can pass any random string that helps it (for instance, in perl
it will be a hash key, most probably)

## Ending:

- when the build program finishes, the connection to the server is 
automatically closed, which is when the server can garbage collect the hash
if it's handling several hashes.


The project consists of a bunch of patches for popular build programs
(make, gmake, ninja, samurai) along with a proof-of-concept server on the
command line.


Rationale: programs like dbp will want to be able to scale up or down the
number of build jobs on a given machine.

For "pervasive computing" this level of control means you can start builds
on your work station, using an adequate number of jobs that still allows
you to use your work station interactively.

But when you step away/go home in the evenings, you may wish to use the full
power of your work station to keep building.

Programs like make or ninja have (mostly) fast turn-arounds: a compile job
rarely takes more than a few minutes (helloooo C++) and so the load-average
difference should happen really fast.

