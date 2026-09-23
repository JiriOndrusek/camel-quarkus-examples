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
package org.acme.ingest.quickstart;

import java.util.List;
import java.util.concurrent.TimeUnit;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The one-line pipeline ingests the bundled manual and semantic search cites it. */
@QuarkusTest
class QuickstartTest {

    @Test
    void bundledManualBecomesSearchable() {
        await().atMost(120, TimeUnit.SECONDS).pollInterval(1, TimeUnit.SECONDS).untilAsserted(() -> {
            List<String> hits = RestAssured.given()
                    .queryParam("q", "What power supply does the Frobnicator need?")
                    .get("/search")
                    .then().statusCode(200)
                    .extract().jsonPath().getList("text", String.class);
            assertTrue(hits.stream().anyMatch(text -> text.contains("EUROPA-MK1")),
                    "the bundled manual must be ingested and retrievable, got: " + hits);
        });

        String document = RestAssured.given()
                .queryParam("q", "What power supply does the Frobnicator need?")
                .get("/search")
                .then().statusCode(200)
                .extract().jsonPath().getString("[0].document");
        assertTrue(document.contains("frobnicator-manual.txt"),
                "retrieval must cite the source document, got: " + document);
    }
}
