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

import java.util.function.Supplier;

import dev.langchain4j.data.segment.TextSegment;
import dev.langchain4j.model.embedding.EmbeddingModel;
import dev.langchain4j.rag.DefaultRetrievalAugmentor;
import dev.langchain4j.rag.RetrievalAugmentor;
import dev.langchain4j.rag.content.retriever.EmbeddingStoreContentRetriever;
import dev.langchain4j.store.embedding.EmbeddingStore;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

/**
 * The RAG wiring: retrieval reads the same embedding store and model the ingestion pipeline
 * writes with, so one embedding space serves both sides. Referenced explicitly from
 * {@code @RegisterAiService(retrievalAugmentor = ...)} — the documented contract, independent
 * of any CDI autowiring.
 */
@ApplicationScoped
public class ManualsAugmentor implements Supplier<RetrievalAugmentor> {

    private final RetrievalAugmentor augmentor;

    public ManualsAugmentor(EmbeddingStore<TextSegment> store, EmbeddingModel model) {
        this.augmentor = DefaultRetrievalAugmentor.builder()
                .contentRetriever(EmbeddingStoreContentRetriever.builder()
                        .embeddingStore(store)
                        .embeddingModel(model)
                        .maxResults(4)
                        .build())
                .build();
    }

    @Override
    public RetrievalAugmentor get() {
        return augmentor;
    }

    /** The same augmentor as a bean, so {@code /chat/preview} can show what RAG retrieves. */
    @Produces
    @Singleton
    RetrievalAugmentor retrievalAugmentor() {
        return augmentor;
    }
}
