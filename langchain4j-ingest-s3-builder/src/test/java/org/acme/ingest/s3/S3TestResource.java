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

import java.net.URI;
import java.util.Map;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import org.eclipse.microprofile.config.ConfigProvider;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;

/**
 * The S3-compatible docker container backing the pipeline in tests: creates the bucket and
 * points the application's {@code s3.endpoint-override} at the mapped port.
 */
public class S3TestResource implements QuarkusTestResourceLifecycleManager {

    private static final int PORT = 4566;
    static final String BUCKET = "manuals";
    static final String ACCESS_KEY = "test";
    static final String SECRET_KEY = "test";

    static volatile String endpoint;

    private GenericContainer<?> container;

    @Override
    public Map<String, String> start() {
        DockerImageName imageName = DockerImageName.parse(
                ConfigProvider.getConfig().getValue("floci.container.image", String.class));
        container = new GenericContainer<>(imageName)
                .withExposedPorts(PORT)
                .waitingFor(Wait.forHttp("/_floci/health").forPort(PORT))
                .withEnv("AWS_ACCESS_KEY_ID", ACCESS_KEY)
                .withEnv("AWS_SECRET_ACCESS_KEY", SECRET_KEY);
        container.start();
        endpoint = "http://" + container.getHost() + ":" + container.getMappedPort(PORT);

        try (S3Client client = s3Client()) {
            client.createBucket(CreateBucketRequest.builder().bucket(BUCKET).build());
        }

        return Map.of("s3.endpoint-override", endpoint);
    }

    /** For seeding and mutating the bucket from tests. */
    static S3Client s3Client() {
        return S3Client.builder()
                .endpointOverride(URI.create(endpoint))
                .region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(ACCESS_KEY, SECRET_KEY)))
                .forcePathStyle(true)
                .build();
    }

    @Override
    public void stop() {
        if (container != null) {
            container.stop();
        }
    }
}
