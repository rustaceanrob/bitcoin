# src/node/

The [`src/node/`](./) directory contains code that needs to access node state
(state in `CChain`, `CBlockIndex`, `CCoinsView`, `CTxMemPool`, and similar
classes).

This directory is at the moment
sparsely populated. Eventually more substantial files like
[`src/validation.cpp`](../validation.cpp) and
[`src/txmempool.cpp`](../txmempool.cpp) might be moved there.
