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

static int
bounds_check_arr( ulong data_sz,
                  ulong ele_off,
                  ulong ele_sz,
                  ulong ele_cnt ) {
  ulong ele_tot;
  if( FD_UNLIKELY( __builtin_umull_overflow( ele_sz, ele_cnt, &ele_tot ) ) )
    return 0;
  ulong ele_hi;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( ele_off, ele_tot, &ele_hi ) ) )
    return 0;
  if( FD_UNLIKELY( ele_hi>data_sz ) )
    return 0;
  return 1;
}

static int
bounds_check( ulong data_sz,
              ulong ele_off,
              ulong ele_sz ) {
  ulong ele_hi;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( ele_off, ele_sz, &ele_hi ) ) )
    return 0;
  if( FD_UNLIKELY( ele_hi>data_sz ) )
    return 0;
  return 1;
}

static void
check_view_snapshot_hashes( ulong size,
                            fd_gossip_view_snapshot_hashes_t const * v ) {
  assert( bounds_check( size, v->full_off, 40UL ) );
  assert( bounds_check_arr( size, v->inc_off, 40UL, v->inc_len ) );
}

static void
check_view_crds_value( uchar const * data,
                       ulong         size,
                       fd_gossip_view_crds_value_t const * v ) {
  (void)data;
  assert( bounds_check( size, v->pubkey_off, sizeof(fd_pubkey_t) ) );
  assert( bounds_check_arr( size, v->value_off, 1UL, v->length ) );
  switch( v->tag ) {
  case FD_GOSSIP_VALUE_LEGACY_CONTACT_INFO:
    break;
  case FD_GOSSIP_VALUE_VOTE:
    assert( bounds_check_arr( size, v->vote->txn_off, 1UL, v->vote->txn_sz ) );
    break;
  case FD_GOSSIP_VALUE_LOWEST_SLOT:
    break;
  case FD_GOSSIP_VALUE_LEGACY_SNAPSHOT_HASHES:
    break;
  case FD_GOSSIP_VALUE_ACCOUNT_HASHES:
    break;
  case FD_GOSSIP_VALUE_EPOCH_SLOTS:
    break;
  case FD_GOSSIP_VALUE_LEGACY_VERSION:
    break;
  case FD_GOSSIP_VALUE_VERSION:
    break;
  case FD_GOSSIP_VALUE_NODE_INSTANCE:
    break;
  case FD_GOSSIP_VALUE_DUPLICATE_SHRED:
    assert( bounds_check_arr( size, v->duplicate_shred->chunk_off, 1UL, v->duplicate_shred->chunk_len ) );
    break;
  case FD_GOSSIP_VALUE_INC_SNAPSHOT_HASHES:
    check_view_snapshot_hashes( size, v->snapshot_hashes );
    break;
  case FD_GOSSIP_VALUE_CONTACT_INFO:
    break;
  case FD_GOSSIP_VALUE_RESTART_LAST_VOTED_FORK_SLOTS:
    break;
  case FD_GOSSIP_VALUE_RESTART_HEAVIEST_FORK:
    break;
  default:
    printf("invalid CRDS value tag %u\n", v->tag);
    abort();
  }
}

// compile with fuzz engine:
// CC=clang EXTRAS=fuzz make fuzz_gossip_msg_parse
// run with:
// build/native/clang/fuzz-test/fuzz_gossip_msg_parse

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  // fuzzer should easily figure this out
  // given that its the second check in msg_parse
  // if( FD_UNLIKELY( size>1232UL ) ) return -1;

  fd_gossip_view_t view[1];
  ulong fd_ret = fd_gossip_msg_parse( view, data, size );
  ulong agave_ret = agave_gossip_msg_parse(data, size);

  // check fd invariants first if fd parsed succesfully
  if (fd_ret != 0) {
    switch( view->tag ) {
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:
      assert( bounds_check_arr( size, view->pull_request->bloom_keys_offset, sizeof(ulong), view->pull_request->bloom_keys_len ) );
      assert( bounds_check_arr( size, view->pull_request->bloom_bits_offset, sizeof(uchar), fd_ulong_align_up( view->pull_request->bloom_bits_cnt, 8UL )/8UL ) );
      break;
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE:
      assert( bounds_check( size, view->pull_response->from_off, sizeof(fd_pubkey_t) ) );
      for( ulong i=0UL; i<(view->pull_response->crds_values_len); i++ ) {
        check_view_crds_value( data, size, &view->pull_response->crds_values[i] );
      }
      break;
    case FD_GOSSIP_MESSAGE_PUSH:
      assert( bounds_check( size, view->push->from_off, sizeof(fd_pubkey_t) ) );
      for( ulong i=0UL; i<(view->push->crds_values_len); i++ ) {
        check_view_crds_value( data, size, &view->push->crds_values[i] );
      }
      break;
    case FD_GOSSIP_MESSAGE_PRUNE:
      assert( bounds_check( size, view->prune->pubkey_off, sizeof(fd_pubkey_t) ) );
      assert( bounds_check_arr( size, view->prune->origins_off, sizeof(fd_pubkey_t), view->prune->origins_len ) );
      assert( bounds_check( size, view->prune->destination_off, sizeof(fd_pubkey_t) ) );
      assert( bounds_check( size, view->prune->signature_off, 64UL ) );
      break;
    case FD_GOSSIP_MESSAGE_PING:
      assert( bounds_check( size, view->ping_pong_off, sizeof(fd_gossip_view_ping_t) ) );
      break;
    case FD_GOSSIP_MESSAGE_PONG:
      assert( bounds_check( size, view->ping_pong_off, sizeof(fd_gossip_view_pong_t) ) );
      break;
    default:
      printf("invalid gossip msg tag %u\n", view->tag);
      abort();
    }
  }

  // now check if the result is the same as agave
  int fd_success = (fd_ret > 0);
  int agave_success = (agave_ret > 0);
  if (fd_success != agave_success) {
    printf("fd result != agave result\n");
    printf("FD RETURN=%lu\n", fd_ret);
    printf("AGAVE RETURN=%lu\n", agave_ret);
    abort();
  }

  return 0;
}
