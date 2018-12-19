# Set Up

To compile the code, you'll need to clone two repositories into this directory.
    git clone https://github.com/RedisLabs/RedisModuleSDK
    git clone https://github.com/antirez/redis
And symlink files in:
    ln -s redis/src/redismodule.h redismodule.h
    ln -s RedisModulesSDK/rmutil/util.h util.h

# Development

See TODO file in repository root.
