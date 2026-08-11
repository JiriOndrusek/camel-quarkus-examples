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
package org.acme.ingest.sync;

import java.util.List;
import java.util.Map;

import dev.langchain4j.data.segment.TextSegment;
import dev.langchain4j.model.embedding.EmbeddingModel;
import dev.langchain4j.store.embedding.EmbeddingSearchRequest;
import dev.langchain4j.store.embedding.EmbeddingStore;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import org.apache.camel.quarkus.component.langchain4j.ingest.IngestOperations;

/**
 * Search plus the corrections API: an admin (or a legal hold, or a webhook) fixing the
 * knowledge base from code — with guarantees. {@code delete} sticks even while the source file
 * still exists; {@code upsert} over a source-owned document pins it so the next pass does not
 * silently revert the correction.
 */
@Path("/kb")
public class KnowledgeBaseResource {

    @Inject
    EmbeddingStore<TextSegment> store;

    @Inject
    EmbeddingModel model;

    @Inject
    IngestOperations ingest;

    @GET
    @Path("/search")
    @Produces(MediaType.APPLICATION_JSON)
    public List<Map<String, Object>> search(@QueryParam("q") String question) {
        return store.search(EmbeddingSearchRequest.builder()
                .queryEmbedding(model.embed(question).content())
                .maxResults(3)
                .build())
                .matches().stream()
                .map(match -> Map.<String, Object> of(
                        "score", match.score(),
                        "document", String.valueOf(match.embedded().metadata().getString("cq_document_id")),
                        "text", match.embedded().text()))
                .toList();
    }

    /** Correct a document from code; the source stops updating it until {@code /unpin}. */
    @POST
    @Path("/documents/{documentId:.+}")
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Object> upsert(@PathParam("documentId") String documentId, String content) {
        var result = ingest.upsert("manuals", documentId, content);
        return Map.of("outcome", result.outcome().label(), "segmentsWritten", result.segmentsWritten());
    }

    /** A legal hold: stays deleted even while the source file still exists. */
    @DELETE
    @Path("/documents/{documentId:.+}")
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Object> delete(@PathParam("documentId") String documentId) {
        return Map.of("outcome", ingest.delete("manuals", documentId).outcome().label());
    }

    @POST
    @Path("/documents/{documentId:.+}/unpin")
    public void unpin(@PathParam("documentId") String documentId) {
        ingest.unpin("manuals", documentId);
    }

    @POST
    @Path("/documents/{documentId:.+}/unsuppress")
    public void unsuppress(@PathParam("documentId") String documentId) {
        ingest.unsuppress("manuals", documentId);
    }
}
