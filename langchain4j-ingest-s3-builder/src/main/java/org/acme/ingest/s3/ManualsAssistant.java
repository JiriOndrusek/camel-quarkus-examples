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

import dev.langchain4j.service.SystemMessage;
import dev.langchain4j.service.UserMessage;
import io.quarkiverse.langchain4j.RegisterAiService;

/**
 * A Quarkus LangChain4j AI service over the knowledge base the pipeline maintains. No RAG
 * wiring: the ingest extension auto-produces a {@code RetrievalAugmentor} for the pipeline, and
 * {@code @RegisterAiService} picks it up as the CDI default — questions are answered from
 * whatever the S3 bucket currently contains.
 */
@RegisterAiService
public interface ManualsAssistant {

    @SystemMessage("You answer questions about product manuals, strictly from the provided context. "
            + "If the context does not contain the answer, say you do not know.")
    String answer(@UserMessage String question);
}
