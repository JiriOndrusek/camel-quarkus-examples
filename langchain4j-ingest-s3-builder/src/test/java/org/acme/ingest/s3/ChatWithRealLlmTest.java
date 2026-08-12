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

import java.util.Map;
import java.util.concurrent.TimeUnit;

import io.quarkus.test.common.WithTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The full chain against a REAL LLM: S3 object → ingested → retrieved by the auto-produced
 * RetrievalAugmentor → answered by a chat model that Ollama Dev Services starts (or a locally
 * running Ollama, which Dev Services detects and reuses).
 *
 * <p>
 * Opt-in — the first run downloads the Ollama image and the model (~1.3 GB, cached in
 * {@code ~/.ollama} afterwards):
 *
 * <pre>
 * mvn clean test -Dtest-llm=true
 * </pre>
 */
@WithTestResource(S3TestResource.class)
@TestProfile(ChatWithRealLlmTest.OllamaDevServiceProfile.class)
@EnabledIfSystemProperty(named = "test-llm", matches = "true")
@QuarkusTest
class ChatWithRealLlmTest {

    @Test
    void assistantAnswersFromTheBucket() {
        IngestS3BuilderTest.putObject("guides/widget.txt", "The WIDGET-MK1 requires a 12 volt supply.");

        await().atMost(120, TimeUnit.SECONDS).pollInterval(1, TimeUnit.SECONDS).untilAsserted(
                () -> assertTrue(IngestS3BuilderTest.search("What supply does the widget require?")
                        .stream().anyMatch(text -> text.contains("WIDGET-MK1")),
                        "the object must be ingested before asking the assistant"));

        String answer = RestAssured.given()
                .queryParam("q", "What supply does the WIDGET-MK1 require?")
                .get("/chat")
                .then().statusCode(200)
                .extract().asString();

        // the model name is invented, so the answer can only come from the retrieved context;
        // LLM output is not deterministic, hence the deliberately loose assertion
        assertTrue(answer.toLowerCase().contains("volt") || answer.contains("12"),
                "the assistant must answer from the ingested manual, got: " + answer);
    }

    /** Switches Ollama Dev Services on and picks a model small enough for a test. */
    public static class OllamaDevServiceProfile implements QuarkusTestProfile {

        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "quarkus.langchain4j.ollama.devservices.enabled", "true",
                    "quarkus.langchain4j.ollama.chat-model.model-id", "llama3.2:1b",
                    "quarkus.langchain4j.ollama.timeout", "120s");
        }
    }
}
