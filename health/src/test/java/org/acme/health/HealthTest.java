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
package org.acme.health;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.containsInAnyOrder;

@QuarkusTest
public class HealthTest {

    @Test
    public void testHealth() throws InterruptedException {
        RestAssured.get("/q/health")
                .then()
                .statusCode(503)
                .body("status", is("DOWN"),
                        "checks.status", containsInAnyOrder("DOWN", "UP"),
                        "checks.name",
                        containsInAnyOrder("camel-readiness-checks", "camel-liveness-checks"),
                        "checks.data.context", containsInAnyOrder(null, "UP"));
    }
}
