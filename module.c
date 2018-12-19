#define _GNU_SOURCE
#define REDISMODULE_EXPERIMENTAL_API

#include "redismodule.h"
#include "util.c"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcre.h>

#include <pthread.h>
#include <unistd.h>

#include <time.h>

#define OVECCOUNT 90

pcre *SimpleCompileRegex(const char *pattern, char ** errmsg) {
  const char *error;
  int erroffset;
  pcre *re = pcre_compile(
    pattern,              /* the pattern */
    0,                    /* default options */
    &error,               /* for error message */
    &erroffset,           /* for error offset */
    NULL);
  if (re == NULL) {
    char *buf;
    size_t sz;
    sz = snprintf(NULL, 0, "PCRE compilation failed at offset %d: %s", erroffset, error);
    buf = (char *)RedisModule_Alloc(sz + 1); /* make sure you check for != NULL in real code */
    snprintf(buf, sz+1, "PCRE compilation failed at offset %d: %s", erroffset, error);
    *errmsg = buf;
  }
  return re;
}

int CheckCompiledRegexOnString(const pcre *regex, const char *str) {
  int subject_length = (int)strlen(str);
  int ovector[OVECCOUNT];
  int rc = pcre_exec(
    regex,                /* the compiled pattern */
    NULL,                 /* no extra data - we didn't study the pattern */
    str,              /* the subject string */
    subject_length,       /* the length of the subject */
    0,                    /* start at offset 0 in the subject */
    0,                    /* default options */
    ovector,              /* output vector for substring information */
    OVECCOUNT); /* number of elements in the output vector */
  if (rc < 0)
    {
    // Some details about why it didn't match. See "Error return values from pcre_exec() in man pcreapi" (or line 1832)
    // switch(rc)
    //   {
    //   case PCRE_ERROR_NOMATCH: printf("No match\n"); break;
    //   /*
    //   Handle other special cases if you like
    //   */
    //   default: printf("Matching error %d\n", rc); break;
    //   }
    return rc;
  }
  return 1;
}

struct ZHRegexCtx {
  RedisModuleCtx *ctx;
  RedisModuleBlockedClient *bc;
  const pcre *regex;
  const int regex_match;
  const int invert;
  RedisModuleString *source_set;
  RedisModuleString *target_set;
  RedisModuleString *hash_key;
  const char *prefix;
  const char *constraint;
  long long *count;
};

/*
1 = Error, string_val
2 = LongLong, long_long_val
*/
struct ZHRegexReply {
  int type;
  char *string_val;
  long long long_long_val;
};

int ZHRegex_Reply(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    REDISMODULE_NOT_USED(argv);
    REDISMODULE_NOT_USED(argc);
    struct ZHRegexReply *reply = RedisModule_GetBlockedClientPrivateData(ctx);
    if (reply->type == 1) {
      return RedisModule_ReplyWithError(ctx,reply->string_val);
    } else if (reply->type == 2) {
      return RedisModule_ReplyWithLongLong(ctx,reply->long_long_val);
    } else {
      return RedisModule_ReplyWithError(ctx, "Invalid reply type");
    }
}

int ZHRegex_Timeout(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    printf("TIMES UP\n");
    REDISMODULE_NOT_USED(argv);
    REDISMODULE_NOT_USED(argc);
    return RedisModule_ReplyWithSimpleString(ctx,"Request timedout");
}

void ZHRegex_FreeData(RedisModuleCtx *ctx, void *privdata) {
    // RedisModule_Free(privdata);
    // I shouldn't not free stuff... but eh, redis's automagical stuff should get it.
}

/* The thread entry point that actually executes the blocking part
 * of the command HELLO.BLOCK. */
void *ZHRegex_ThreadMain(void *arg) {
    struct ZHRegexCtx *targ = arg;

    RedisModuleBlockedClient *bc = targ->bc;
    RedisModuleCtx *ctx = targ->ctx;
    const char *prefix = targ->prefix;
    const char *constraint = targ->constraint;
    const int regex_match = targ->regex_match;
    const int inverted = targ->invert;
    const pcre *regex = targ->regex;
    long long count = *targ->count;
    RedisModuleString *hash_key = RedisModule_CreateStringFromString(ctx, targ->hash_key);
    RedisModuleString *source_set = targ->source_set;
    RedisModuleString *target_set = targ->target_set;

    struct ZHRegexReply *reply = RedisModule_Alloc(sizeof(struct ZHRegexReply *));

    RedisModule_ThreadSafeContextLock(ctx);

    RedisModuleKey *source_key =
        RedisModule_OpenKey(ctx, source_set, REDISMODULE_READ);

    if (RedisModule_KeyType(source_key) != REDISMODULE_KEYTYPE_ZSET) {
      RedisModule_CloseKey(source_key);
      RedisModule_ThreadSafeContextUnlock(ctx);
      reply->type = 1;
      reply->string_val = REDISMODULE_ERRORMSG_WRONGTYPE;
      RedisModule_UnblockClient(bc, reply);
      printf("Exited safely early because of WRONGTYPE error in source_key\n");
      return NULL;
    }

    RedisModuleKey *target_key =
        RedisModule_OpenKey(ctx, target_set, REDISMODULE_READ | REDISMODULE_WRITE);

    if ((RedisModule_KeyType(target_key) != REDISMODULE_KEYTYPE_ZSET) &&
        (RedisModule_KeyType(target_key) != REDISMODULE_KEYTYPE_EMPTY)) {
      RedisModule_CloseKey(source_key);
      RedisModule_CloseKey(target_key);
      RedisModule_ThreadSafeContextUnlock(ctx);
      reply->type = 1;
      reply->string_val = REDISMODULE_ERRORMSG_WRONGTYPE;
      RedisModule_UnblockClient(bc, reply);
      printf("Exited safely early because of WRONGTYPE error in target_key\n");
      return NULL;
    }

    RedisModule_ZsetFirstInScoreRange(source_key, REDISMODULE_NEGATIVE_INFINITE, REDISMODULE_POSITIVE_INFINITE, 0, 0);

    long long counter = 0;
    long long index = 0;
    long long nindex = 0;
    long long non_existance_counter = 0;
    int res;

    do {
      double score;
      RedisModuleString *relement = RedisModule_ZsetRangeCurrentElement(source_key, &score);
      const char *element  = RedisModule_StringPtrLen(relement, NULL);
      char *key_to_check = RedisModule_Alloc(strlen(prefix) + strlen(element) + 1);
      strcpy(key_to_check, prefix);
      strcat(key_to_check, element);

      RedisModuleString *rkey_to_check = RedisModule_CreateString(ctx, key_to_check, strlen(key_to_check));

      RedisModuleKey *element_key =
          RedisModule_OpenKey(ctx, rkey_to_check, REDISMODULE_READ);
      RedisModule_FreeString(ctx, rkey_to_check);
      RedisModule_Free(key_to_check);

      if ((RedisModule_KeyType(element_key) != REDISMODULE_KEYTYPE_HASH) &&
          (RedisModule_KeyType(element_key) != REDISMODULE_KEYTYPE_EMPTY)) {
        RedisModule_CloseKey(source_key);
        RedisModule_CloseKey(target_key);
        RedisModule_CloseKey(element_key);
        RedisModule_ThreadSafeContextUnlock(ctx);
        reply->type = 1;
        reply->string_val = REDISMODULE_ERRORMSG_WRONGTYPE;
        RedisModule_UnblockClient(bc, reply);
        printf("Exited safely early because of WRONGTYPE error in element_key\n");
        return NULL;
      }

      if (RedisModule_KeyType(element_key) == REDISMODULE_KEYTYPE_EMPTY) {
        RedisModule_CloseKey(element_key);
        printf("Key empty, moving on\n");
        continue;
      }

      if (RedisModule_KeyType(element_key) != REDISMODULE_KEYTYPE_HASH) {
        RedisModule_CloseKey(element_key);
        printf("Key not a hash (and not empty), moving on\n");
        continue;
      }

      if (RedisModule_StringPtrLen(hash_key, NULL) == NULL) {
        RedisModule_CloseKey(element_key);
        printf("Hash key is null\n");
        continue;
      }

      RedisModuleString *rhash_value;
      RedisModule_HashGet(element_key, REDISMODULE_HASH_NONE, hash_key, &rhash_value, NULL);
      if (rhash_value == NULL) {
        printf("No value for key\n");
        RedisModule_CloseKey(element_key);
        continue;
      }
      const char *hash_value = RedisModule_StringPtrLen(rhash_value, NULL);
      RedisModule_FreeString(ctx, rhash_value);

      if (regex_match) {
        // 1 is match, -1 is no match, less than -1 is error.
        res = CheckCompiledRegexOnString(regex, hash_value);
        if ((res == 1) ^ inverted) {
          counter = counter + 1;
          RedisModule_ZsetAdd(target_key, score, relement, NULL);
          RedisModule_FreeString(ctx, relement);
        }
        if (res != 1 && res != -1) {
          printf("Got an error %d with teh regex\n", res);
        }
      } else {
        if ((strcasestr(constraint, hash_value) != NULL) ^ inverted) {
          counter = counter + 1;
          RedisModule_ZsetAdd(target_key, score, relement, NULL);
          RedisModule_FreeString(ctx, relement);
        }
      }

      RedisModule_CloseKey(element_key);

      if (count != -1 && counter == count) {
        printf("Exiting early; reached count\n");
        break;
      }

      if (index%200 == 0) {
        RedisModule_CloseKey(source_key);
        RedisModule_CloseKey(target_key);
        RedisModule_ThreadSafeContextUnlock(ctx);

        struct timespec tim, tim2;
        tim.tv_sec = 0;
        tim.tv_nsec = 100;
        nanosleep(&tim , &tim2);

        RedisModule_ThreadSafeContextLock(ctx);

        source_key = RedisModule_OpenKey(ctx, source_set, REDISMODULE_READ);

        if (RedisModule_KeyType(source_key) != REDISMODULE_KEYTYPE_ZSET) {
          RedisModule_CloseKey(source_key);
          RedisModule_ThreadSafeContextUnlock(ctx);
          reply->type = 1;
          reply->string_val = REDISMODULE_ERRORMSG_WRONGTYPE;
          RedisModule_UnblockClient(bc, reply);
          printf("Exited safely early because of WRONGTYPE error in source_key\n");
          return NULL;
        }

        target_key = RedisModule_OpenKey(ctx, target_set, REDISMODULE_READ | REDISMODULE_WRITE);

        if ((RedisModule_KeyType(target_key) != REDISMODULE_KEYTYPE_ZSET) &&
            (RedisModule_KeyType(target_key) != REDISMODULE_KEYTYPE_EMPTY)) {
          RedisModule_CloseKey(source_key);
          RedisModule_CloseKey(target_key);
          RedisModule_ThreadSafeContextUnlock(ctx);
          reply->type = 1;
          reply->string_val = REDISMODULE_ERRORMSG_WRONGTYPE;
          RedisModule_UnblockClient(bc, reply);
          printf("Exited safely early because of WRONGTYPE error in target_key\n");
          return NULL;
        }

        RedisModule_ZsetFirstInScoreRange(source_key, REDISMODULE_NEGATIVE_INFINITE, REDISMODULE_POSITIVE_INFINITE, 0, 0);

        nindex = 0;
        do {
          RedisModule_ZsetRangeNext(source_key);
          nindex = nindex + 1;
        } while (nindex < index);

        // double tmp_score;
        // do {
        //   RedisModuleString *tmp_relement = RedisModule_ZsetRangeCurrentElement(source_key, &tmp_score);
        //   const char *tmp_element  = strdup(RedisModule_StringPtrLen(tmp_relement, NULL));
        //   if (strcmp(tmp_element, element) == 0 && tmp_score == score) {
        //     break;
        //   }
        //   printf("Skipping element..\n");
        //   RedisModule_ZsetRangeNext(source_key);
        // } while(1==1);
      }

      index = index + 1;
    } while (RedisModule_ZsetRangeNext(source_key) != 0);

    printf("Didn't exist %lld times\n", non_existance_counter);

    RedisModule_CloseKey(source_key);
    RedisModule_CloseKey(target_key);
    RedisModule_ThreadSafeContextUnlock(ctx);
    reply->type = 2;
    reply->long_long_val = counter;
    RedisModule_UnblockClient(bc,reply);
    return NULL;
}

int ZHRegex_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    // I don't like having this, but eh:
    RedisModule_AutoMemory(ctx);

    unsigned int regex_match = 1; // 0 = substr, 1 = regex
    unsigned int invert = 0; // 0 = normal, 1 = inverted
    long long count;
    // <src_set> <target_set> <prefix> <key> <regex

    int arg_count = 6;
    if (RMUtil_ArgExists("invert", argv, argc, 6) != 0) {
      arg_count = arg_count + 1;
      invert = 1;
    }
    if (RMUtil_ArgExists("like", argv, argc, 6) != 0) {
      arg_count = arg_count + 1;
      regex_match = 0;
    }
    int count_offset = RMUtil_ArgExists("count", argv, argc, 6);
    if (count_offset != 0) {
      arg_count = arg_count + 2;
      if (RMUtil_ParseArgsAfter("COUNT", argv, argc, "l", &count) != REDISMODULE_OK) {
        const char *offending_parameter = RedisModule_StringPtrLen(argv[count_offset+1], NULL);
        char *buf;
        size_t sz;
        sz = snprintf(NULL, 0, "ERR Invalid paramter '%s' passed for COUNT", offending_parameter);
        buf = (char *)RedisModule_Alloc(sz + 1); /* make sure you check for != NULL in real code */
        snprintf(buf, sz+1, "ERR Invalid paramter '%s' passed for COUNT", offending_parameter);
        return RedisModule_ReplyWithError(ctx, buf);
      }
      printf("Found count in args, set to %lld\n", count);
    } else {
      count = -1;
      printf("No count in args, set to %lld\n", count);
    }
    if (argc != arg_count) {
      return RedisModule_WrongArity(ctx);
    }

    RedisModuleString *source_set = argv[1];
    RedisModuleString *target_set = argv[2];

    size_t prefix_len;
    const char *prefix_raw     = RedisModule_StringPtrLen(argv[3], &prefix_len);
    char *prefix;
    prefix = RedisModule_Alloc(sizeof(char) * (prefix_len + 1));
    strcpy(prefix,prefix_raw);

    RedisModuleString *hash_key = argv[4];

    size_t constraint_len;
    const char *constraint_raw  = RedisModule_StringPtrLen(argv[5], &constraint_len);
    char *constraint;
    constraint = RedisModule_Alloc(sizeof(char) * (constraint_len + 1));
    strcpy(constraint,constraint_raw);

    pcre *regex = NULL;
    if (regex_match) {
      printf("Compiling regex %s\n", constraint);
      char *errmsg;
      regex = SimpleCompileRegex(constraint, &errmsg);

      printf("Compiled regex\n");

      if (regex == NULL) {
        printf("Regex compilation failed; Returning ERR\n");
        RedisModule_ReplyWithError(ctx, errmsg);
        RedisModule_Free(errmsg);
        return REDISMODULE_ERR;
      }

      printf("Regex compilation sucessful\n");
    }
    if (regex == NULL) {
      printf("Warning: Regex is null (regex_match %d)\n", regex_match);
    }

    pthread_t tid;
    RedisModuleBlockedClient *bc = RedisModule_BlockClient(ctx,ZHRegex_Reply,ZHRegex_Timeout,ZHRegex_FreeData,0);

    long long *count_ptr = RedisModule_Alloc(sizeof(long long));
    *count_ptr = count;
    struct ZHRegexCtx rarg = {
      .ctx = RedisModule_GetThreadSafeContext(bc),
      .bc = bc,
      .source_set = source_set,
      .target_set = target_set,
      .regex_match = regex_match,
      .invert = invert,
      .prefix = prefix,
      .constraint = constraint,
      .regex = regex,
      .hash_key = hash_key,
      .count = count_ptr
    };
    struct ZHRegexCtx *targ = &rarg;

    // void RedisModule_SetDisconnectCallback(RedisModuleBlockedClient *bc, RedisModuleDisconnectFunc callback);

    if (pthread_create(&tid,NULL,ZHRegex_ThreadMain,(void*)targ) != 0) {
        RedisModule_AbortBlock(bc);
        return RedisModule_ReplyWithError(ctx,"-ERR Can't start thread");
    }
    return REDISMODULE_OK;
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (RedisModule_Init(ctx,"zhregex",1,REDISMODULE_APIVER_1)
        == REDISMODULE_ERR) return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx,"zhregex",
        ZHRegex_RedisCommand, "write", 0,0,0) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    return REDISMODULE_OK;
}
