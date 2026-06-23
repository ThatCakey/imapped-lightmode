# Protocol Notes

This document records what the current IMAP frontend advertises and what it intentionally keeps disabled.

## Advertised now

- `IMAP4rev1`
- `STARTTLS`
- `AUTH=PLAIN`
- `UIDPLUS`
- `IDLE`
- `NAMESPACE`
- `SPECIAL-USE`
- `UNSELECT`
- `ENABLE`
- `CONDSTORE`
- `ESEARCH`
- `SORT`
- `MOVE`

## Implemented command surface

- `CAPABILITY`
- `NOOP`
- `LOGOUT`
- `STARTTLS`
- `LOGIN`
- `SELECT`
- `EXAMINE`
- `CREATE`
- `DELETE`
- `RENAME`
- `SUBSCRIBE`
- `UNSUBSCRIBE`
- `LIST`
- `LSUB`
- `STATUS`
- `APPEND`
- `CHECK`
- `CLOSE`
- `EXPUNGE`
- `SEARCH`
- `FETCH`
- `STORE`
- `COPY`
- `UID`

## Implementation notes

- FETCH supports raw RFC822 reads, partial fetches, and common metadata items.
- SEARCH uses PostgreSQL for structured fields and Tantivy for text-oriented queries.
- The sync engine preserves raw message bytes and uses content-addressed object storage.
- Unsupported capabilities should not be advertised until the implementation is complete.

## Gaps

The project still has feature areas that are intentionally incomplete compared with the full objective, including a full workspace split, advanced QRESYNC behavior, and complete MIME blob persistence.
