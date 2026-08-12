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

import java.util.List;
import java.util.concurrent.TimeUnit;

import io.quarkus.test.common.WithTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The {@code @Ingest}-builder pipeline against the S3 container: object put → searchable,
 * overwrite (new ETag) → replaced without duplicates, delete → removed by reconciliation.
 */
@WithTestResource(S3TestResource.class)
@QuarkusTest
class IngestS3BuilderTest {

    @Test
    void bucketIsMirroredIntoTheKnowledgeBase() {
        putObject("guides/widget.txt", "The WIDGET-MK1 requires a 12 volt supply.");

        await().atMost(120, TimeUnit.SECONDS).pollInterval(1, TimeUnit.SECONDS).untilAsserted(() -> {
            List<String> hits = search("What supply does the widget require?");
            assertTrue(hits.stream().anyMatch(text -> text.contains("WIDGET-MK1")),
                    "the object must be ingested, got: " + hits);
        });

        // the same knowledge reaches any @RegisterAiService through the auto-produced
        // RetrievalAugmentor — preview the augmented prompt without calling an LLM
        String prompt = RestAssured.given()
                .queryParam("q", "What supply does the widget require?")
                .get("/chat/preview")
                .then().statusCode(200)
                .extract().asString();
        assertTrue(prompt.contains("WIDGET-MK1"),
                "the retrieved context must be incorporated into the prompt, got: " + prompt);

        putObject("guides/widget.txt", "The WIDGET-MK2 requires a 24 volt supply.");

        await().atMost(120, TimeUnit.SECONDS).pollInterval(1, TimeUnit.SECONDS).untilAsserted(() -> {
            List<String> hits = search("What supply does the widget require?");
            assertTrue(hits.stream().anyMatch(text -> text.contains("WIDGET-MK2")),
                    "the overwritten object (new ETag) must be re-ingested, got: " + hits);
            assertFalse(hits.stream().anyMatch(text -> text.contains("WIDGET-MK1")),
                    "the previous version must be replaced, not joined, got: " + hits);
        });

        try (S3Client client = S3TestResource.s3Client()) {
            client.deleteObject(DeleteObjectRequest.builder()
                    .bucket(S3TestResource.BUCKET).key("guides/widget.txt").build());
        }

        await().atMost(120, TimeUnit.SECONDS).pollInterval(1, TimeUnit.SECONDS).untilAsserted(() -> {
            List<String> hits = search("What supply does the widget require?");
            assertFalse(hits.stream().anyMatch(text -> text.contains("WIDGET")),
                    "a deleted object must disappear from the knowledge base, got: " + hits);
        });
    }

    @Test
    void pipelineGatesReadinessUntilItsFirstPass() {
        await().atMost(120, TimeUnit.SECONDS).pollInterval(1, TimeUnit.SECONDS).untilAsserted(
                () -> RestAssured.get("/q/health/ready").then().statusCode(200));
    }

    static void putObject(String key, String content) {
        try (S3Client client = S3TestResource.s3Client()) {
            client.putObject(PutObjectRequest.builder()
                    .bucket(S3TestResource.BUCKET).key(key).build(),
                    RequestBody.fromString(content));
        }
    }

    static List<String> search(String question) {
        return RestAssured.given()
                .queryParam("q", question)
                .get("/search")
                .then()
                .statusCode(200)
                .extract().jsonPath().getList("text", String.class);
    }
}
