use super::*;

impl CortexService {
    pub async fn index_ai_roots(
        &self,
        path: Option<String>,
        force: bool,
        since: Option<String>,
    ) -> ServiceResult<scanner::IndexResult> {
        self.index_ai_roots_with_scan_budget(
            path,
            force,
            since,
            None,
            None,
            std::collections::BTreeMap::new(),
        )
        .await
    }

    pub(crate) async fn index_ai_roots_with_scan_budget(
        &self,
        path: Option<String>,
        force: bool,
        since: Option<String>,
        scan_budget: Option<scanner::ScanBudget>,
        start_after: Option<std::path::PathBuf>,
        discovery_start_after: std::collections::BTreeMap<std::path::PathBuf, std::path::PathBuf>,
    ) -> ServiceResult<scanner::IndexResult> {
        let storage = self.storage.clone();
        let since_mtime_nanos = since
            .as_deref()
            .map(|raw| parse_required_timestamp(raw, "since"))
            .transpose()?
            .map(|dt| {
                dt.timestamp_nanos_opt().ok_or_else(|| {
                    ServiceError::InvalidInput(
                        "since timestamp out of i64 nanoseconds range".to_string(),
                    )
                })
            })
            .transpose()?;
        self.run_db("index_ai_roots", move |pool| {
            scanner::index_roots_with_options(
                pool,
                scanner::IndexOptions {
                    root_override: path.map(std::path::PathBuf::from),
                    force,
                    since_mtime_nanos,
                    scan_budget,
                    start_after,
                    discovery_start_after,
                },
                Some(&storage),
            )
        })
        .await
        .map_err(classify_scanner_error)
    }

    pub async fn add_ai_file(
        &self,
        file: String,
        force: bool,
    ) -> ServiceResult<scanner::IndexResult> {
        let storage = self.storage.clone();
        self.run_db("add_ai_file", move |pool| {
            scanner::index_file_with_options(
                pool,
                std::path::Path::new(&file),
                "explicit_file",
                scanner::IndexFileOptions {
                    force,
                    ..Default::default()
                },
                Some(&storage),
            )
        })
        .await
        .map_err(classify_scanner_error)
    }

    pub async fn list_ai_checkpoints(
        &self,
        errors_only: bool,
        missing_only: bool,
        limit: Option<u32>,
    ) -> ServiceResult<Vec<scanner::CheckpointEntry>> {
        self.run_db("list_ai_checkpoints", move |pool| {
            scanner::list_checkpoints(
                pool,
                &scanner::CheckpointListOptions {
                    errors_only,
                    missing_only,
                    limit,
                },
            )
        })
        .await
    }

    pub async fn list_ai_parse_errors(
        &self,
        limit: Option<u32>,
    ) -> ServiceResult<Vec<scanner::ParseErrorEntry>> {
        self.run_db("list_ai_parse_errors", move |pool| {
            scanner::list_parse_errors(pool, &scanner::ParseErrorListOptions { limit })
        })
        .await
    }

    async fn prune_ai_checkpoints(
        &self,
        missing_only: bool,
        dry_run: bool,
        limit: Option<u32>,
    ) -> ServiceResult<scanner::PruneCheckpointsResult> {
        self.run_db("prune_ai_checkpoints", move |pool| {
            scanner::prune_checkpoints(
                pool,
                &scanner::PruneCheckpointsOptions {
                    missing_only,
                    dry_run,
                    limit,
                },
            )
        })
        .await
    }

    pub async fn prune_ai_checkpoints_checked(
        &self,
        req: models::AiPruneCheckpointsRequest,
    ) -> ServiceResult<scanner::PruneCheckpointsResult> {
        req.validate_admin()?;
        self.prune_ai_checkpoints(req.missing_only, req.dry_run, req.limit)
            .await
    }

    pub async fn ai_doctor(&self) -> ServiceResult<scanner::AiDoctorReport> {
        let db_path = self.storage.db_path.clone();
        self.run_db("ai_doctor", move |pool| scanner::ai_doctor(pool, &db_path))
            .await
    }

    pub async fn ai_indexing_health(
        &self,
        process_start_time: Option<String>,
    ) -> ServiceResult<scanner::AiIndexingHealth> {
        self.run_db("ai_indexing_health", move |pool| {
            scanner::ai_indexing_health(pool, process_start_time.as_deref())
        })
        .await
    }
}

fn classify_scanner_error(error: ServiceError) -> ServiceError {
    match error {
        ServiceError::Internal(err) if scanner_error_is_invalid_input(&err) => {
            ServiceError::InvalidInput(err.to_string())
        }
        other => other,
    }
}

fn scanner_error_is_invalid_input(error: &anyhow::Error) -> bool {
    scanner::is_invalid_input_error(error)
}
