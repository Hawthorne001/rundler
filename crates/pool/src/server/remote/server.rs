// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

#![allow(clippy::result_large_err)]

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use alloy_primitives::{Address, B256};
use async_trait::async_trait;
use futures_util::StreamExt;
use rundler_task::{
    grpc::{grpc_metrics::GrpcMetricsLayer, protos::from_bytes},
    GracefulShutdown, TaskSpawner,
};
use rundler_types::{
    chain::ChainSpec,
    pool::{Pool, Reputation},
    EntityUpdate, UserOperationId, UserOperationVariant,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{transport::Server, Request, Response, Result, Status};

use super::protos::{
    add_op_response, admin_set_tracking_response, debug_clear_state_response,
    debug_dump_mempool_response, debug_dump_paymaster_balances_response,
    debug_dump_reputation_response, debug_set_reputation_response, get_op_by_hash_response,
    get_op_by_id_response, get_ops_by_hashes_response, get_ops_response,
    get_ops_summaries_response, get_reputation_status_response, get_stake_status_response,
    op_pool_server::{OpPool, OpPoolServer},
    remove_op_by_id_response, remove_ops_response, update_entities_response, AddOpRequest,
    AddOpResponse, AddOpSuccess, AdminSetTrackingRequest, AdminSetTrackingResponse,
    AdminSetTrackingSuccess, DebugClearStateRequest, DebugClearStateResponse,
    DebugClearStateSuccess, DebugDumpMempoolRequest, DebugDumpMempoolResponse,
    DebugDumpMempoolSuccess, DebugDumpPaymasterBalancesRequest, DebugDumpPaymasterBalancesResponse,
    DebugDumpPaymasterBalancesSuccess, DebugDumpReputationRequest, DebugDumpReputationResponse,
    DebugDumpReputationSuccess, DebugSetReputationRequest, DebugSetReputationResponse,
    DebugSetReputationSuccess, GetOpByHashRequest, GetOpByHashResponse, GetOpByHashSuccess,
    GetOpByIdRequest, GetOpByIdResponse, GetOpByIdSuccess, GetOpsByHashesRequest,
    GetOpsByHashesResponse, GetOpsByHashesSuccess, GetOpsRequest, GetOpsResponse, GetOpsSuccess,
    GetOpsSummariesRequest, GetOpsSummariesResponse, GetOpsSummariesSuccess,
    GetReputationStatusRequest, GetReputationStatusResponse, GetReputationStatusSuccess,
    GetStakeStatusRequest, GetStakeStatusResponse, GetStakeStatusSuccess,
    GetSupportedEntryPointsRequest, GetSupportedEntryPointsResponse, MempoolOp,
    PoolOperationSummary, RemoveOpByIdRequest, RemoveOpByIdResponse, RemoveOpByIdSuccess,
    RemoveOpsRequest, RemoveOpsResponse, RemoveOpsSuccess, ReputationStatus,
    SubscribeNewHeadsRequest, SubscribeNewHeadsResponse, TryUoFromProto, UpdateEntitiesRequest,
    UpdateEntitiesResponse, UpdateEntitiesSuccess, OP_POOL_FILE_DESCRIPTOR_SET,
};
use crate::server::local::LocalPoolHandle;

const MAX_REMOTE_BLOCK_SUBSCRIPTIONS: usize = 32;

pub(crate) async fn remote_mempool_server_task(
    task_spawner: Box<dyn TaskSpawner>,
    chain_spec: ChainSpec,
    local_pool: LocalPoolHandle,
    addr: SocketAddr,
    shutdown: GracefulShutdown,
) {
    // gRPC server
    let pool_impl = OpPoolImpl::new(chain_spec, local_pool, task_spawner);
    let op_pool_server = OpPoolServer::new(pool_impl);
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(OP_POOL_FILE_DESCRIPTOR_SET)
        .build_v1()
        .expect("failed to build reflection service");

    // health service
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<OpPoolServer<OpPoolImpl>>()
        .await;

    let metrics_layer = GrpcMetricsLayer::new("op_pool_service".to_string());

    if let Err(e) = Server::builder()
        .layer(metrics_layer)
        .add_service(op_pool_server)
        .add_service(reflection_service)
        .add_service(health_service)
        .serve_with_shutdown(addr, async move {
            let _ = shutdown.await;
        })
        .await
    {
        tracing::error!("pool server failed: {e:?}");
    }
}

struct OpPoolImpl {
    chain_spec: ChainSpec,
    local_pool: LocalPoolHandle,
    num_block_subscriptions: Arc<AtomicUsize>,
    task_spawner: Box<dyn TaskSpawner>,
}

impl OpPoolImpl {
    pub(crate) fn new(
        chain_spec: ChainSpec,
        local_pool: LocalPoolHandle,
        task_spawner: Box<dyn TaskSpawner>,
    ) -> Self {
        Self {
            chain_spec,
            local_pool,
            num_block_subscriptions: Arc::new(AtomicUsize::new(0)),
            task_spawner,
        }
    }

    fn get_entry_point(&self, req_entry_point: &[u8]) -> Result<Address> {
        from_bytes(req_entry_point)
            .map_err(|e| Status::invalid_argument(format!("Invalid entry point: {e}")))
    }

    fn get_address(&self, address: &[u8]) -> Result<Address> {
        from_bytes(address).map_err(|e| Status::invalid_argument(format!("Invalid address: {e}")))
    }
}

#[async_trait]
impl OpPool for OpPoolImpl {
    async fn get_supported_entry_points(
        &self,
        _request: Request<GetSupportedEntryPointsRequest>,
    ) -> Result<Response<GetSupportedEntryPointsResponse>> {
        let resp = match self.local_pool.get_supported_entry_points().await {
            Ok(entry_points) => GetSupportedEntryPointsResponse {
                chain_id: self.chain_spec.id,
                entry_points: entry_points.into_iter().map(|ep| ep.to_vec()).collect(),
            },
            Err(e) => {
                return Err(Status::internal(format!("Failed to get entry points: {e}")));
            }
        };

        Ok(Response::new(resp))
    }

    async fn add_op(&self, request: Request<AddOpRequest>) -> Result<Response<AddOpResponse>> {
        let req = request.into_inner();

        let proto_op = req
            .op
            .ok_or_else(|| Status::invalid_argument("Operation is required in AddOpRequest"))?;
        let uo =
            UserOperationVariant::try_uo_from_proto(proto_op, &self.chain_spec).map_err(|e| {
                Status::invalid_argument(format!("Failed to convert to UserOperation: {e}"))
            })?;
        let permissions = req
            .permissions
            .ok_or_else(|| Status::invalid_argument("Permissions are required in AddOpRequest"))?
            .try_into()
            .map_err(|e| {
                Status::invalid_argument(format!(
                    "Failed to convert to UserOperationPermissions: {e}"
                ))
            })?;

        let resp = match self.local_pool.add_op(uo, permissions).await {
            Ok(hash) => AddOpResponse {
                result: Some(add_op_response::Result::Success(AddOpSuccess {
                    hash: hash.to_vec(),
                })),
            },
            Err(error) => AddOpResponse {
                result: Some(add_op_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn get_ops(&self, request: Request<GetOpsRequest>) -> Result<Response<GetOpsResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;

        let filter_id = if req.filter_id.is_empty() {
            None
        } else {
            Some(req.filter_id)
        };

        let resp = match self.local_pool.get_ops(ep, req.max_ops, filter_id).await {
            Ok(ops) => GetOpsResponse {
                result: Some(get_ops_response::Result::Success(GetOpsSuccess {
                    ops: ops.iter().map(MempoolOp::from).collect(),
                })),
            },
            Err(error) => GetOpsResponse {
                result: Some(get_ops_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn get_ops_summaries(
        &self,
        request: Request<GetOpsSummariesRequest>,
    ) -> Result<Response<GetOpsSummariesResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;

        let filter_id = if req.filter_id.is_empty() {
            None
        } else {
            Some(req.filter_id)
        };

        let resp = match self
            .local_pool
            .get_ops_summaries(ep, req.max_ops, filter_id)
            .await
        {
            Ok(summaries) => GetOpsSummariesResponse {
                result: Some(get_ops_summaries_response::Result::Success(
                    GetOpsSummariesSuccess {
                        summaries: summaries
                            .into_iter()
                            .map(PoolOperationSummary::from)
                            .collect(),
                    },
                )),
            },
            Err(error) => GetOpsSummariesResponse {
                result: Some(get_ops_summaries_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn get_ops_by_hashes(
        &self,
        request: Request<GetOpsByHashesRequest>,
    ) -> Result<Response<GetOpsByHashesResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;
        let hashes: Vec<B256> = req
            .hashes
            .into_iter()
            .map(|h| {
                from_bytes(&h).map_err(|e| Status::invalid_argument(format!("Invalid hash: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let resp = match self.local_pool.get_ops_by_hashes(ep, hashes).await {
            Ok(ops) => GetOpsByHashesResponse {
                result: Some(get_ops_by_hashes_response::Result::Success(
                    GetOpsByHashesSuccess {
                        ops: ops.iter().map(MempoolOp::from).collect(),
                    },
                )),
            },
            Err(error) => GetOpsByHashesResponse {
                result: Some(get_ops_by_hashes_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }
    async fn get_op_by_hash(
        &self,
        request: Request<GetOpByHashRequest>,
    ) -> Result<Response<GetOpByHashResponse>> {
        let req = request.into_inner();

        let hash = from_bytes(&req.hash).map_err(|e| {
            Status::invalid_argument(format!("Invalid hash in GetOpByHashRequest: {e}"))
        })?;

        let resp = match self.local_pool.get_op_by_hash(hash).await {
            Ok(op) => GetOpByHashResponse {
                result: Some(get_op_by_hash_response::Result::Success(
                    GetOpByHashSuccess {
                        op: op.map(|op| MempoolOp::from(&op)),
                    },
                )),
            },
            Err(error) => GetOpByHashResponse {
                result: Some(get_op_by_hash_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn get_op_by_id(
        &self,
        request: Request<GetOpByIdRequest>,
    ) -> Result<Response<GetOpByIdResponse>> {
        let req = request.into_inner();

        let resp = match self
            .local_pool
            .get_op_by_id(UserOperationId {
                sender: from_bytes(&req.sender)
                    .map_err(|e| Status::invalid_argument(format!("Invalid sender: {e}")))?,
                nonce: from_bytes(&req.nonce)
                    .map_err(|e| Status::invalid_argument(format!("Invalid nonce: {e}")))?,
            })
            .await
        {
            Ok(op) => GetOpByIdResponse {
                result: Some(get_op_by_id_response::Result::Success(GetOpByIdSuccess {
                    op: op.map(|op| MempoolOp::from(&op)),
                })),
            },
            Err(error) => GetOpByIdResponse {
                result: Some(get_op_by_id_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn remove_ops(
        &self,
        request: Request<RemoveOpsRequest>,
    ) -> Result<Response<RemoveOpsResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;

        let hashes: Vec<B256> = req
            .hashes
            .into_iter()
            .map(|h| {
                if h.len() != 32 {
                    return Err(Status::invalid_argument("Hash must be 32 bytes long"));
                }
                Ok(B256::from_slice(&h))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let resp = match self.local_pool.remove_ops(ep, hashes).await {
            Ok(_) => RemoveOpsResponse {
                result: Some(remove_ops_response::Result::Success(RemoveOpsSuccess {})),
            },
            Err(error) => RemoveOpsResponse {
                result: Some(remove_ops_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn remove_op_by_id(
        &self,
        request: Request<RemoveOpByIdRequest>,
    ) -> Result<Response<RemoveOpByIdResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;

        let resp = match self
            .local_pool
            .remove_op_by_id(
                ep,
                UserOperationId {
                    sender: from_bytes(&req.sender)
                        .map_err(|e| Status::invalid_argument(format!("Invalid sender: {e}")))?,
                    nonce: from_bytes(&req.nonce)
                        .map_err(|e| Status::invalid_argument(format!("Invalid nonce: {e}")))?,
                },
            )
            .await
        {
            Ok(hash) => RemoveOpByIdResponse {
                result: Some(remove_op_by_id_response::Result::Success(
                    RemoveOpByIdSuccess {
                        hash: hash.map_or(vec![], |h| h.to_vec()),
                    },
                )),
            },
            Err(error) => RemoveOpByIdResponse {
                result: Some(remove_op_by_id_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn update_entities(
        &self,
        request: Request<UpdateEntitiesRequest>,
    ) -> Result<Response<UpdateEntitiesResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;
        let entity_updates = req
            .entity_updates
            .iter()
            .map(|eu| eu.try_into())
            .collect::<Result<Vec<EntityUpdate>, _>>()
            .map_err(|e| {
                Status::internal(format!("Failed to convert to proto entity update: {}", e))
            })?;

        let resp = match self.local_pool.update_entities(ep, entity_updates).await {
            Ok(_) => UpdateEntitiesResponse {
                result: Some(update_entities_response::Result::Success(
                    UpdateEntitiesSuccess {},
                )),
            },
            Err(error) => UpdateEntitiesResponse {
                result: Some(update_entities_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn debug_clear_state(
        &self,
        request: Request<DebugClearStateRequest>,
    ) -> Result<Response<DebugClearStateResponse>> {
        let req = request.into_inner();
        let resp = match self
            .local_pool
            .debug_clear_state(req.clear_mempool, req.clear_paymaster, req.clear_reputation)
            .await
        {
            Ok(_) => DebugClearStateResponse {
                result: Some(debug_clear_state_response::Result::Success(
                    DebugClearStateSuccess {},
                )),
            },
            Err(error) => DebugClearStateResponse {
                result: Some(debug_clear_state_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn admin_set_tracking(
        &self,
        request: Request<AdminSetTrackingRequest>,
    ) -> Result<Response<AdminSetTrackingResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;
        let resp = match self
            .local_pool
            .admin_set_tracking(ep, req.paymaster, req.reputation)
            .await
        {
            Ok(_) => AdminSetTrackingResponse {
                result: Some(admin_set_tracking_response::Result::Success(
                    AdminSetTrackingSuccess {},
                )),
            },
            Err(error) => AdminSetTrackingResponse {
                result: Some(admin_set_tracking_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn debug_dump_mempool(
        &self,
        request: Request<DebugDumpMempoolRequest>,
    ) -> Result<Response<DebugDumpMempoolResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;

        let resp = match self.local_pool.debug_dump_mempool(ep).await {
            Ok(ops) => DebugDumpMempoolResponse {
                result: Some(debug_dump_mempool_response::Result::Success(
                    DebugDumpMempoolSuccess {
                        ops: ops.iter().map(MempoolOp::from).collect(),
                    },
                )),
            },
            Err(error) => DebugDumpMempoolResponse {
                result: Some(debug_dump_mempool_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn debug_set_reputation(
        &self,
        request: Request<DebugSetReputationRequest>,
    ) -> Result<Response<DebugSetReputationResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;

        let reps = if req.reputations.is_empty() {
            return Err(Status::invalid_argument(
                "Reputation is required in DebugSetReputationRequest",
            ));
        } else {
            req.reputations
        };

        let reps = reps
            .into_iter()
            .map(|r| r.try_into())
            .collect::<Result<Vec<Reputation>, _>>()
            .map_err(|e| {
                Status::internal(format!("Failed to convert from proto reputation {e}"))
            })?;

        let resp = match self.local_pool.debug_set_reputations(ep, reps).await {
            Ok(_) => DebugSetReputationResponse {
                result: Some(debug_set_reputation_response::Result::Success(
                    DebugSetReputationSuccess {},
                )),
            },
            Err(error) => DebugSetReputationResponse {
                result: Some(debug_set_reputation_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn get_reputation_status(
        &self,
        request: Request<GetReputationStatusRequest>,
    ) -> Result<Response<GetReputationStatusResponse>> {
        let req = request.into_inner();

        let address = self.get_address(&req.address)?;
        let entry_point = self.get_entry_point(&req.entry_point)?;

        let resp = match self
            .local_pool
            .get_reputation_status(entry_point, address)
            .await
        {
            Ok(status) => GetReputationStatusResponse {
                result: Some(get_reputation_status_response::Result::Success(
                    GetReputationStatusSuccess {
                        status: ReputationStatus::from(status).into(),
                    },
                )),
            },
            Err(error) => GetReputationStatusResponse {
                result: Some(get_reputation_status_response::Result::Failure(
                    error.into(),
                )),
            },
        };

        Ok(Response::new(resp))
    }

    async fn get_stake_status(
        &self,
        request: Request<GetStakeStatusRequest>,
    ) -> Result<Response<GetStakeStatusResponse>> {
        let req = request.into_inner();

        let address = self.get_address(&req.address)?;
        let entry_point = self.get_entry_point(&req.entry_point)?;

        let resp = match self.local_pool.get_stake_status(entry_point, address).await {
            Ok(status) => GetStakeStatusResponse {
                result: Some(get_stake_status_response::Result::Success(
                    GetStakeStatusSuccess {
                        status: Some(status.into()),
                    },
                )),
            },
            Err(error) => GetStakeStatusResponse {
                result: Some(get_stake_status_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn debug_dump_reputation(
        &self,
        request: Request<DebugDumpReputationRequest>,
    ) -> Result<Response<DebugDumpReputationResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;

        let resp = match self.local_pool.debug_dump_reputation(ep).await {
            Ok(reps) => DebugDumpReputationResponse {
                result: Some(debug_dump_reputation_response::Result::Success(
                    DebugDumpReputationSuccess {
                        reputations: reps.into_iter().map(Into::into).collect(),
                    },
                )),
            },
            Err(error) => DebugDumpReputationResponse {
                result: Some(debug_dump_reputation_response::Result::Failure(
                    error.into(),
                )),
            },
        };

        Ok(Response::new(resp))
    }

    async fn debug_dump_paymaster_balances(
        &self,
        request: Request<DebugDumpPaymasterBalancesRequest>,
    ) -> Result<Response<DebugDumpPaymasterBalancesResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;

        let resp = match self.local_pool.debug_dump_paymaster_balances(ep).await {
            Ok(balances) => DebugDumpPaymasterBalancesResponse {
                result: Some(debug_dump_paymaster_balances_response::Result::Success(
                    DebugDumpPaymasterBalancesSuccess {
                        balances: balances.into_iter().map(Into::into).collect(),
                    },
                )),
            },
            Err(error) => DebugDumpPaymasterBalancesResponse {
                result: Some(debug_dump_paymaster_balances_response::Result::Failure(
                    error.into(),
                )),
            },
        };

        Ok(Response::new(resp))
    }

    type SubscribeNewHeadsStream = UnboundedReceiverStream<Result<SubscribeNewHeadsResponse>>;

    async fn subscribe_new_heads(
        &self,
        request: Request<SubscribeNewHeadsRequest>,
    ) -> Result<Response<Self::SubscribeNewHeadsStream>> {
        let (tx, rx) = mpsc::unbounded_channel();

        if self.num_block_subscriptions.fetch_add(1, Ordering::Relaxed)
            >= MAX_REMOTE_BLOCK_SUBSCRIPTIONS
        {
            self.num_block_subscriptions.fetch_sub(1, Ordering::Relaxed);
            return Err(Status::resource_exhausted("Too many block subscriptions"));
        }

        let req = request.into_inner();
        let to_track = req
            .to_track
            .into_iter()
            .map(|a| from_bytes(&a))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Status::invalid_argument(format!("Invalid address: {e}")))?;

        let num_block_subscriptions = Arc::clone(&self.num_block_subscriptions);
        let mut new_heads = match self.local_pool.subscribe_new_heads(to_track).await {
            Ok(new_heads) => new_heads,
            Err(error) => {
                tracing::error!("Failed to subscribe to new blocks: {error}");
                return Err(Status::internal(format!(
                    "Failed to subscribe to new blocks: {error}"
                )));
            }
        };

        self.task_spawner.spawn(Box::pin(async move {
            loop {
                match new_heads.next().await {
                    Some(new_head) => {
                        if tx
                            .send(Ok(SubscribeNewHeadsResponse {
                                new_head: Some(new_head.into()),
                            }))
                            .is_err()
                        {
                            break;
                        }
                    }
                    None => {
                        tracing::warn!("new block subscription closed");
                        break;
                    }
                }
            }
            num_block_subscriptions.fetch_sub(1, Ordering::Relaxed);
        }));

        Ok(Response::new(UnboundedReceiverStream::new(rx)))
    }
}
