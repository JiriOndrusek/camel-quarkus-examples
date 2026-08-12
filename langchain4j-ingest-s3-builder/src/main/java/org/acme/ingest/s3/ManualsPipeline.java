/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.acme.ingest.s3;

import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;
import org.apache.camel.quarkus.component.langchain4j.ingest.Ingest;
import org.apache.camel.quarkus.component.langchain4j.ingest.IngestPipeline;
import org.apache.camel.quarkus.component.langchain4j.ingest.Source;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * The ingestion pipeline declared in Java: the {@code @Ingest} builder is the type-safe twin of
 * the {@code quarkus.camel.ai.ingest.*} configuration — every option has a properties
 * equivalent. The topology lives in code where the IDE can help; connection details stay in
 * configuration, where they can differ per environment (the tests point them at an
 * S3-compatible container).
 */
@ApplicationScoped
public class ManualsPipeline {

    @ConfigProperty(name = "s3.bucket")
    String bucket;

    @ConfigProperty(name = "s3.region")
    String region;

    @ConfigProperty(name = "s3.access-key")
    String accessKey;

    @ConfigProperty(name = "s3.secret-key")
    String secretKey;

    /** Set for S3-compatible stores (MinIO, floci); leave empty for real AWS. */
    @ConfigProperty(name = "s3.endpoint-override")
    Optional<String> endpointOverride;

    @Ingest("manuals")
    IngestPipeline manuals() {
        // object keys are the document ids, ETags the change fingerprints — available from
        // the bucket listing, so unchanged objects are never even downloaded
        Source source = Source.s3(bucket)
                .region(region)
                .accessKey(accessKey)
                .secretKey(secretKey)
                .pollInterval(2000);
        endpointOverride.ifPresent(source::endpointOverride);

        return IngestPipeline.from(source)
                // sync: the knowledge base MIRRORS the bucket — an overwritten object
                // replaces its previous vectors, a deleted object disappears, an unchanged
                // bucket costs nothing on restart. The sync ledger lives in the application's
                // datasource; the embedding store and model are resolved automatically since
                // exactly one of each exists here (pgvector + the local ONNX model).
                .sync()
                // pgvector overwrites on same-id writes (measured), so replacement is an upsert
                .writeStrategy("upsert")
                // bump if the embedding model ever changes, so the corpus re-embeds instead of
                // silently mixing two embedding spaces
                .embeddingModelId("all-minilm-l6-v2@1")
                // deletion safety: a pass refusing to delete more than half the corpus needs
                // explicit consent (allowBulkDelete)
                .bulkDeleteThreshold(0.5)
                .splitter("recursive", 500, 50);
    }
}
