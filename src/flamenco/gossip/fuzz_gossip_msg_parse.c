#include "fd_gossip_private.h"
#include <assert.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>

#define LIBAGAVE_GOSSIP_PARSE "/home/hrvoje/agave_gossip_parse/target/release/libagave_gossip_parse.so"

typedef ulong (*agave_gossip_msg_parse_t)(uchar const *, ulong);
static agave_gossip_msg_parse_t agave_gossip_msg_parse;

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  fd_log_level_stderr_set(4);
  atexit( fd_halt );

  // load agave msg parse lib
  void *handle = dlopen(LIBAGAVE_GOSSIP_PARSE, RTLD_LAZY);
  if (handle == NULL) {
    perror("dlopen");
    abort();
  }

  agave_gossip_msg_parse = (agave_gossip_msg_parse_t)dlsym(
    handle,
    "agave_gossip_msg_parse"
  );
  if (agave_gossip_msg_parse == NULL) {
    perror("dlsym");
    abort();
  }

  return 0;
}

// compile with fuzz engine:
// CC=clang EXTRAS=fuzz make fuzz_gossip_msg_parse

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  // fuzzer should easily figure this out
  // given that its the second check in msg_parse
  // if( FD_UNLIKELY( size>1232UL ) ) return -1;

  fd_gossip_view_t view[1];
  ulong fd_ret = fd_gossip_msg_parse( view, data, size );
  ulong agave_ret = agave_gossip_msg_parse(data, size);

  int fd_success = (fd_ret > 0);
  int agave_success = (agave_ret > 0);
  if (fd_success != agave_success) {
    printf("FD RETURN=%lu\n", fd_ret);
    printf("AGAVE RETURN=%lu\n", agave_ret);
    abort();
  }

  return 0;
}
