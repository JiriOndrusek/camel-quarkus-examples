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
 * the {@code quarkus.camel.langchain4j.ingest.*} configuration — every option has a properties
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

    /** Set for S3-compatible stores (MinIO, LocalStack); leave empty for real AWS. */
    @ConfigProperty(name = "s3.endpoint-override")
    Optional<String> endpointOverride;

    @Ingest("manuals")
    IngestPipeline manuals() {
        // the object key is the document id: retrieval cites it, and the register deduplicates
        // by it. deleteAfterRead(false) matters - a knowledge base reads its source, it does
        // not consume it
        return IngestPipeline.from(Source.endpoint(dsl -> {
            var s3 = dsl.aws2S3(bucket)
                    .region(region)
                    .accessKey(accessKey)
                    .secretKey(secretKey)
                    .deleteAfterRead(false)
                    .delay(2000);
            endpointOverride.ifPresent(url -> s3.uriEndpointOverride(url).overrideEndpoint(true));
            return s3;
        })
                .documentId("CamelAwsS3Key")
                // first write wins per key: a re-listed object ingests once. An overwritten
                // object keeps its key, so it is answered skipped, not re-embedded - streams
                // that carry updates need a version-aware id (the synchronising engine that
                // mirrors a changing bucket is a later release)
                .idempotentRepository("manualsRegister")
                .idempotentRepositoryAutoCreate(true))
                .splitter(500, 50);
    }
}
