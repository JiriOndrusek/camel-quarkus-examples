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

import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.rag.AugmentationRequest;
import dev.langchain4j.rag.AugmentationResult;
import dev.langchain4j.rag.RetrievalAugmentor;
import dev.langchain4j.rag.query.Metadata;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

/**
 * The RAG side of the example: {@code /chat} asks the AI service (needs a running Ollama, see
 * the README), {@code /chat/preview} shows what RAG retrieves for a question — the augmented
 * prompt an LLM would receive — without calling any LLM. The injected
 * {@link RetrievalAugmentor} is the same auto-produced bean the AI service uses.
 */
@Path("/chat")
public class ChatResource {

    @Inject
    ManualsAssistant assistant;

    @Inject
    RetrievalAugmentor augmentor;

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String chat(@QueryParam("q") String question) {
        return assistant.answer(question);
    }

    @GET
    @Path("/preview")
    @Produces(MediaType.TEXT_PLAIN)
    public String preview(@QueryParam("q") String question) {
        UserMessage message = UserMessage.from(question);
        AugmentationResult result = augmentor.augment(
                new AugmentationRequest(message, Metadata.from(message, "preview", List.of())));
        return ((UserMessage) result.chatMessage()).singleText();
    }
}
