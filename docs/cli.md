# Rundler CLI

The Rundler Command Line Interface (CLI) offers a wide array of options and subcommands. Most options contain reasonable defaults that can be overridden.

## Subcommands

- `node`: Runs the Pool, Builder, and RPC servers in a single process.
- `rpc`: Runs the Rpc server.
- `pool`: Runs the Pool server.
- `builder`: Runs the Builder server.

The `pool` and `builder` commands will also start a gRPC endpoint to allow other processes to interact with each service.

## Common Options

These options are common to all subcommands and can be used globally:

### Chain Specification

See [chain spec](./architecture/chain_spec.md) for a detailed description of chain spec derivation from these options.

- `--network`: Network to look up a hardcoded chain spec. (default: None)
  - env: *NETWORK*
- `--chain_spec`: Path to a chain spec TOML file.
  - env: *CHAIN_SPEC*
- (env only): Chain specification overrides.
  - env: *CHAIN_**

### Rundler Common

- `--node_http`: EVM Node HTTP URL to use. (**REQUIRED**)
  - env: *NODE_HTTP*
- `--max_verification_gas`: Maximum verification gas. (default: `5000000`).
  - env: *MAX_VERIFICATION_GAS*
- `--max_uo_cost`: Maximum cost of a UO that the mempool will accept. Optional, defaults to MAX (default: `None`).
  - env: *MAX_UO_COST*
- `--min_stake_value`: Minimum stake value. (default: `1000000000000000000`).
  - env: *MIN_STAKE_VALUE*
- `--min_unstake_delay`: Minimum unstake delay. (default: `84600`).
  - env: *MIN_UNSTAKE_DELAY*
- `--tracer_timeout`: The timeout used for custom javascript tracers, the string must be in a valid parseable format that can be used in the `ParseDuration` function on an ethereum node. See Docs [Here](https://pkg.go.dev/time#ParseDuration). (default: `15s`)
  - env: *TRACER_TIMEOUT*
- `--enable_unsafe_fallback`: If set, allows the simulation code to fallback to an unsafe simulation if there is a tracer error. (default: `false`)
  - env: *ENABLE_UNSAFE_FALLBACK*
- `--user_operation_event_block_distance`: Number of blocks to search when calling `eth_getUserOperationByHash`/`eth_getUserOperationReceipt`. (default: all blocks)
  - env: *USER_OPERATION_EVENT_BLOCK_DISTANCE*
- `--user_operation_event_block_distance_fallback`: Number of blocks to search when falling back during `eth_getUserOperationByHash`/`eth_getUserOperationReceipt` upon initial failure using `user_operation_event_block_distance`. (default: None)
  - env: *USER_OPERATION_EVENT_BLOCK_DISTANCE_FALLBACK*
- `--verification_estimation_gas_fee`: The gas fee to use during verification estimation. (default: `1000000000000` 10K gwei).
  - env: *VERIFICATION_ESTIMATION_GAS_FEE*
  - See [RPC documentation](./architecture/rpc.md#verificationGasLimit-estimation) for details.
- `--bundle_base_fee_overhead_percent`: bundle transaction base fee overhead over network pending value. (default: `27`).
  - env: *BUNDLE_BASE_FEE_OVERHEAD_PERCENT*
- `--bundle_priority_fee_overhead_percent`: bundle transaction priority fee overhead over network value. (default: `0`).
  - env: *BUNDLE_PRIORITY_FEE_OVERHEAD_PERCENT*
- `--priority_fee_mode_kind`: Priority fee mode kind. Possible values are `base_fee_percent` and `priority_fee_increase_percent`. (default: `priority_fee_increase_percent`).
  - options: ["base_fee_percent", "priority_fee_increase_percent"]
  - env: *PRIORITY_FEE_MODE_KIND*
- `--priority_fee_mode_value`: Priority fee mode value. (default: `0`).
  - env: *PRIORITY_FEE_MODE_VALUE*
- `--base_fee_accept_percent`: Percentage of the current network fees a user operation must have in order to be accepted into the mempool. (default: `100`).
  - env: *BASE_FEE_ACCEPT_PERCENT*
- `--pre_verification_gas_accept_percent`: Percentage of the required PVG that a user operation must have in order to be accepted into the mempool. Only applies if there is dynamic PVG, else the full amount is required. (default: `50`)
  - env: *PRE_VERIFICATION_GAS_ACCEPT_PERCENT*
- `--execution_gas_limit_efficiency_reject_threshold`: The ratio of execution gas used to gas limit under which to reject UOs upon entry to the mempool (default: `0.0` disabled)
  - env: *EXECUTION_GAS_LIMIT_EFFICIENCY_REJECT_THRESHOLD*
- `--verification_gas_limit_efficiency_reject_threshold`: The ratio of verification gas used to gas limit under which to reject UOs upon entry to the mempool (default: `0.0` disabled)
  - env: *VERIFICATION_GAS_LIMIT_EFFICIENCY_REJECT_THRESHOLD*
- `--verification_gas_allowed_error_pct`: The allowed error percentage during verification gas estimation. (default: 15)
  - env: *VERIFICATION_GAS_ALLOWED_ERROR_PCT*
- `--call_gas_allowed_error_pct`: The allowed error percentage during call gas estimation. (default: 15)
  - env: *CALL_GAS_ALLOWED_ERROR_PCT*
- `--max_gas_estimation_gas`: The gas limit to use during the call to the gas estimation binary search helper functions. (default: 550M)
  - env: *MAX_GAS_ESTIMATION_GAS*
- `--max_gas_estimation_rounds`: The maximum amount of remote RPC calls to make during gas estimation while attempting to converge to the error percentage. (default: 3)
  - env: *MAX_GAS_ESTIMATION_ROUNDS*
- `--aws_region`: AWS region. (default: `us-east-1`).
  - env: *AWS_REGION*
  - (*Only required if using other AWS features*)
- `--unsafe`: Flag for unsafe bundling mode. When set Rundler will skip checking simulation rules (and any `debug_traceCall`). (default: `false`).
  - env: *UNSAFE*
- `--mempool_config_path`: Path to the mempool configuration file. (example: `mempool-config.json`, `s3://my-bucket/mempool-config.json`). (default: `None`)
  - This path can either be a local file path or an S3 url. If using an S3 url, Make sure your machine has access to this file. 
  - env: *MEMPOOL_CONFIG_PATH*
  - See [here](./architecture/pool.md#alternative-mempools-in-preview) for details.
- `--entry_point_builders_path`: Path to the entry point builders configuration file (example: `builders.json`, `s3://my-bucket/builders.json`). (default: `None`)
  - This path can either be a local file path or an S3 url. If using an S3 url, Make sure your machine has access to this file.
  - env: *ENTRY_POINT_BUILDERS_PATH*
  - NOTE: most deployments can ignore this and use the settings below.
  - See [here](./architecture/builder.md#custom) for details.
- `--disable_entry_point_v0_6`: Disable entry point v0.6 support. (default: `false`).
  - env: *DISABLE_ENTRY_POINT_V0_6*
- `--num_builders_v0_6`: The number of bundle builders to run on entry point v0.6 (default: `1`)
  - env: *NUM_BUILDERS_V0_6*
  - NOTE: ignored if `entry_point_builders_path` is set
- `--disable_entry_point_v0_7`: Disable entry point v0.7 support. (default: `false`).
  - env: *DISABLE_ENTRY_POINT_V0_7*
- `--num_builders_v0_7`: The number of bundle builders to run on entry point v0.7 (default: `1`)
  - env: *NUM_BUILDERS_V0_7*
  - NOTE: ignored if `entry_point_builders_path` is set
- `--da_gas_tracking_enabled`: Enable the DA gas tracking feature of the mempool (default: `false`)
  - env: *DA_GAS_TRACKING_ENABLED*
- `--max_expected_storage_slots`: Optionally set the maximum number of expected storage slots to submit with a conditional transaction. (default: `None`)
  - env: *MAX_EXPECTED_STORAGE_SLOTS*
- `--enabled_aggregators`: List of enabled aggregators.
  - env: *ENABLED_AGGREGATORS*
  - Types: see [aggregator.rs](../bin/rundler/src/cli/aggregator.rs)
- `--aggregator_options`: List of aggregator specific options
  - env: *ENABLED_AGGREGATORS*
  - List of KEY=VALUE delimited by ',': i.e. `ENABLED_AGGREGATORS="KEY1=VALUE1,KEY2=VALUE2"`
  - Options: see [aggregator.rs](../bin/rundler/src/cli/aggregator.rs)

## Metrics Options

Options for the metrics server:

- `--metrics.port`: Port to listen on for metrics requests. default: `8080`.
  - env: *METRICS_PORT*
- `--metrics.host`: Host to listen on for metrics requests. default: `0.0.0.0`.
  - env: *METRICS_HOST*
- `--metrics.tags`: Tags for metrics in the format `key1=value1,key2=value2,...`.
  - env: *METRICS_TAGS*
- `--metrics.sample_interval_millis`: Sample interval to use for sampling metrics. default: `1000`.
  - env: *METRICS_SAMPLE_INTERVAL_MILLIS*

## Logging Options

Options for logging:

- `RUST_LOG` environment variable is used for controlling log level see: [env_logger](https://docs.rs/env_logger/0.10.1/env_logger/#enabling-logging).
Only `level` is supported.
- `--log.file`: Log file. If not provided, logs will be written to stdout.
  - env: *LOG_FILE*
- `--log.json`: If set, logs will be written in JSON format.
  - env: *LOG_JSON*
 - `--log.otlp_grpc_endpoint`: If set, tracing spans will be forwarded to the provided gRPC OTLP endpoint.
  - env: *LOG_OTLP_GRPC_ENDPOINT*

## RPC Options

List of command line options for configuring the RPC API.

- `--rpc.port`:	Port to listen on for JSON-RPC requests (default: `3000`)
  - env: *RPC_PORT*
- `--rpc.host`:	Host to listen on for JSON-RPC requests (default: `0.0.0.0`)
  - env: *RPC_HOST*
- `--rpc.api`:	Which APIs to expose over the RPC interface (default: `eth,rundler`)
  - env: *RPC_API*
- `--rpc.timeout_seconds`:	Timeout for RPC requests (default: `20`)
  - env: *RPC_TIMEOUT_SECONDS*
- `--rpc.max_connections`:	Maximum number of concurrent connections (default: `100`)
  - env: *RPC_MAX_CONNECTIONS*
- `--rpc.corsdomain`: Enable the cors functionality on the server (default: None and therefore corsdomain is disabled).
  - env: *RPC_CORSDOMAIN*
- `--rpc.pool_url`:	Pool URL for RPC (default: `http://localhost:50051`)
  - env: *RPC_POOL_URL*
  - *Only required when running in distributed mode* 
- `--rpc.builder_url`:	Builder URL for RPC (default: `http://localhost:50052`)
  - env: *RPC_BUILDER_URL*
  - *Only required when running in distributed mode* 
- `--rpc.permissions_enabled`: True if user operation permissions are enabled on the RPC API (default: `false`)
  - env: *RPC_PERMISSIONS_ENABLED
  - **NOTE: Do not enable this on a public API - for internal, trusted connections only.**

## Pool Options

List of command line options for configuring the Pool.

- `--pool.port`: Port to listen on for gRPC requests (default: `50051`)
  - env: *POOL_PORT*
  - *Only required when running in distributed mode* 
- `--pool.host`: Host to listen on for gRPC requests (default: `127.0.0.1`)
  - env: *POOL_HOST*
  - *Only required when running in distributed mode* 
- `--pool.max_size_in_bytes`: Maximum size in bytes for the pool (default: `500000000`, `0.5 GB`)
  - env: *POOL_MAX_SIZE_IN_BYTES*
- `--pool.same_sender_mempool_count`: Maximum number of user operations for an unstaked sender (default: `4`)
  - env: *POOL_SAME_SENDER_MEMPOOL_COUNT*
- `--pool.min_replacement_fee_increase_percentage`: Minimum replacement fee increase percentage (default: `10`)
  - env: *POOL_MIN_REPLACEMENT_FEE_INCREASE_PERCENTAGE*
- `--pool.blocklist_path`: Path to a blocklist file (e.g `blocklist.json`, `s3://my-bucket/blocklist.json`)
  - env: *POOL_BLOCKLIST_PATH*
  - This path can either be a local file path or an S3 url. If using an S3 url, Make sure your machine has access to this file. 
  - See [here](./architecture/pool.md#allowlistblocklist) for details.
- `--pool.allowlist_path`: Path to an allowlist file (e.g `allowlist.json`, `s3://my-bucket/allowlist.json`)
  - env: *POOL_ALLOWLIST_PATH*
  - This path can either be a local file path or an S3 url. If using an S3 url, Make sure your machine has access to this file. 
  - See [here](./architecture/pool.md#allowlistblocklist) for details.
- `--pool.chain_poll_interval_millis`: Interval at which the pool polls an Eth node for new blocks (default: `100`)
  - env: *POOL_CHAIN_POLL_INTERVAL_MILLIS*
- `--pool.chain_sync_max_retries`: The amount of times to retry syncing the chain before giving up and waiting for the next block (default: `5`)
  - env: *POOL_CHAIN_SYNC_MAX_RETRIES*
- `--pool.paymaster_tracking_enabled`: Boolean field that sets whether the pool server starts with paymaster tracking enabled (default: `true`)
  - env: *POOL_PAYMASTER_TRACKING_ENABLED*
- `--pool.paymaster_cache_length`: Length of the paymaster cache (default: `10_000`)
  - env: *POOL_PAYMASTER_CACHE_LENGTH*
- `--pool.reputation_tracking_enabled`: Boolean field that sets whether the pool server starts with reputation tracking enabled (default: `true`)
  - env: *POOL_REPUTATION_TRACKING_ENABLED*
- `--pool.drop_min_num_blocks`: The minimum number of blocks that a UO must stay in the mempool before it can be requested to be dropped by the user (default: `10`)
  - env: *POOL_DROP_MIN_NUM_BLOCKS*
- `--pool.max_time_in_pool_secs`: The maximum amount of time a UO is allowed to be in the mempool, in seconds. (default: `None`)
  - env: *POOL_MAX_TIME_IN_POOL_SECS*

## Builder Options

List of command line options for configuring the Builder.

- `--builder.port`: Port to listen on for gRPC requests (default: `50052`)
  - env: *BUILDER_PORT*
  - *Only required when running in distributed mode* 
- `--builder.host`: Host to listen on for gRPC requests (default: `127.0.0.1`)
  - env: *BUILDER_HOST*
  - *Only required when running in distributed mode* 
- `--builder.max_bundle_size`: Maximum number of ops to include in one bundle (default: `128`)
  - env: *BUILDER_MAX_BUNDLE_SIZE*
- `--builder.max_blocks_to_wait_for_mine`: After submitting a bundle transaction, the maximum number of blocks to wait for that transaction to mine before trying to resend with higher gas fees (default: `2`)
  - env: *BUILDER_MAX_BLOCKS_TO_WAIT_FOR_MINE*
- `--builder.replacement_fee_percent_increase`: Percentage amount to increase gas fees when retrying a transaction after it failed to mine (default: `10`)
  - env: *BUILDER_REPLACEMENT_FEE_PERCENT_INCREASE*
- `--builder.max_cancellation_fee_increases`: Maximum number of cancellation fee increases to attempt (default: `15`)
  - env: *BUILDER_MAX_CANCELLATION_FEE_INCREASES*
- `--builder.max_replacement_underpriced_blocks`: The maximum number of blocks to wait in a replacement underpriced state before issuing a cancellation transaction (default: `20`)
  - env: *BUILDER_MAX_REPLACEMENT_UNDERPRICED_BLOCKS*
- `--builder.sender`: Choice of what sender type to use for transaction submission. (default: `raw`, options: `raw`, `flashbots`, `polygon_bloxroute`)
  - env: *BUILDER_SENDER*
- `--builder.submit_url`: Only used if builder.sender == "raw." If present, the URL of the ETH provider that will be used to send transactions. Defaults to the value of `node_http`.
  - env: *BUILDER_SUBMIT_URL*
- `--builder.use_conditional_rpc`: Only used if builder.sender == "raw." Use `eth_sendRawTransactionConditional` when submitting. (default: `false`)
  - env: *BUILDER_USE_CONDITIONAL_RPC*
- `--builder.flashbots_relay_builders`: Only used if builder.sender == "flashbots." Additional builders to send bundles to through the Flashbots relay RPC (comma-separated). List of builders that the Flashbots RPC supports can be found [here](https://docs.flashbots.net/flashbots-auction/advanced/rpc-endpoint#eth_sendprivatetransaction). (default: `flashbots`)
  - env: *BUILDER_FLASHBOTS_RELAY_BUILDERS*
- `--builder.flashbots_relay_auth_key`: Only used/required if builder.sender == "flashbots." Authorization key to use with the flashbots relay. See [here](https://docs.flashbots.net/flashbots-auction/advanced/rpc-endpoint#authentication) for more info. (default: None)
  - env: *BUILDER_FLASHBOTS_RELAY_AUTH_KEY*
- `--builder.bloxroute_auth_header`: Only used/required if builder.sender == "polygon_bloxroute." If using the bloxroute transaction sender on Polygon, this is the auth header to supply with the requests. (default: None)
  - env: *BUILDER_BLOXROUTE_AUTH_HEADER*
- `--builder.pool_url`: If running in distributed mode, the URL of the pool server to use.
  - env: *BUILDER_POOL_URL*
  - *Only required when running in distributed mode*

## Signer Options

- `--signer.private_keys`: Private keys to use for signing transactions, separated by `,`
  - env: *SIGNER_PRIVATE_KEYS*
- `--signer.mnemonic`: Mnemonic to use for signing transactions
  - env: *SIGNER_MNEMONIC*
- `--signer.aws_kms_key_ids`: AWS KMS key IDs to use for signing transactions, separated by `,`. 
  - env: *SIGNER_AWS_KMS_KEY_IDS*
  - To enable signer locking see `SIGNER_ENABLE_KMS_LOCKING`.
- `--signer.aws_kms_grouped_keys`: AWS KMS key ids grouped to keys in `aws_kms_key_ids` Separated by `,`. Groups are made based on the number of signers required. There must be enough signers to make a full group for every entry in `aws_kms_key_ids`.
  - env: *SIGNER_AWS_KMS_GROUPED_KEYS*
- `--signer.enable_kms_locking`: True if keys should be locked before use. Only applies to keys in `aws_kms_key_ids`.
  - env: *SIGNER_ENABLE_KMS_LOCKING*
- `--signer.redis_uri`: Redis URI to use for KMS leasing (default: `""`)
  - env: *SIGNER_REDIS_URI*
  -*Only required when SIGNER_ENABLE_KMS_LOCKING is set* 
- `--signer.redis_lock_ttl_millis`: Redis lock TTL in milliseconds (default: `60000`)
  - env: *SIGNER_REDIS_LOCK_TTL_MILLIS*
  - *Only required when SIGNER_ENABLE_KMS_LOCKING is set* 
- `--signer.enable_kms_funding`: Whether to enable kms funding from `aws_kms_key_ids` to the key ids in `aws_kms_key_groups`. (default: `false`)
  - env: *SIGNER_ENABLE_KMS_FUNDING*
- `--signer.fund_below`: If KMS funding is enabled, this is the signer balance value below which to trigger a funding event
  - env: *SIGNER_FUND_BELOW*
- `--signer.fund_to`: If KMS funding is enabled, this is the signer balance to fund to during a funding event
  - env: *SIGNER_FUND_TO*
- `--signer.funding_txn_poll_interval_ms`: During funding, this is the poll interval for transaction status (default: `1000`)
  - env: *SIGNER_FUNDING_TXN_POLL_INTERVAL_MS*
- `--signer.funding_txn_poll_max_retries`: During funding, this is the maximum amount of time to poll for transaction status before abandoning (default: `20`)
  - env: *SIGNER_FUNDING_TXN_POLL_MAX_RETRIES*
- `--signer.funding_txn_priority_fee_multiplier`: During funding, this is the multiplier to apply to the network priority fee (default: `2.0`)
  - env: *SIGNER_FUNDING_TXN_PRIORITY_FEE_MULTIPLIER*
- `--signer.funding_txn_base_fee_multiplier`: During funding, this is the multiplier to apply to the network base fee (default: `2.0`)
  - env: *SIGNER_FUNDING_TXN_BASE_FEE_MULTIPLIER*

### Signing schemes

Rundler supports multiple ways to sign bundle transactions. In configuration precedence order: 

1. KMS locked master key with funded sub-keys: `--signer.enable_kms_funding`
2. Private keys: `--signer.private_keys`
3. Mnemonic: `--signer.mnemonic`
4. KMS locked keys: `--signer.aws_kms_key_ids`

#### KMS Locking

If `--signer.enable_kms_locking` is set, keys that are listed in `--signer.aws_kms_key_ids` are always locked before usage so that they can be safely shared across multiple Rundler instances without nonce issues.

Locking uses Redis and thus a Redis URL must be provided to Rundler for key leasing to make sure keys are not accessed at the same time from concurrent processes.

#### KMS Funding

If `--signer.enable_kms_funding` is set this scheme will be enabled. It will look for subkeys in the following precedence order:

1. `aws_kms_grouped_keys`: Must have enough signers to make a full group for each `aws_kms_key_ids`. Group size is based on number of signers requested.
    - If locking is enabled, once a funding KMS key is locked, the corresponding group is used for all subkeys.
    - Else, the first group is always used
2. `private_keys`: Private keys for the subkeys. The same list applies regardless of which KMS key is locked.
3. `mnemonic`: Supports a `mnemonic` from which multiple subkeys can be derived. The same `mnemonic` applies regardless of which KMS key is locked

When funding is enabled, Rundler will run a background process that will fund keys whose balance has fallen below `fund_below` with a transaction from the funding key that increases their balance to `fund_to`.

## Example Usage

Here are some example commands to use the CLI:

```sh
# Run the Node subcommand with custom options
$ ./rundler node --network dev --disable_entry_point_v0_6 --node_http http://localhost:8545 --signer.private_keys 0x0000000000000000000000000000000000000000000000000000000000000001

# Run the RPC subcommand with custom options and enable JSON logging. The builder (localhost:50052) and pool (localhost:50051) will need to be running before this starts.
$ ./rundler rpc --network dev --node_http http://localhost:8545 --log.json --disable_entry_point_v0_6

# Run the Pool subcommand with custom options and specify a mempool config file
$ ./target/debug/rundler pool --network dev --max_simulate_handle_ops_gas 15000000 --mempool_config_path mempool.json --node_http http://localhost:8545 --disable_entry_point_v0_6
```
