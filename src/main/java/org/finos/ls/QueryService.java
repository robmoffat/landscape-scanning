package org.finos.ls;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.finos.ls.queries.QueryType;
import org.finos.scan.github.client.Organization;
import org.finos.scan.github.client.Repository;
import org.finos.scan.github.client.RepositoryConnection;
import org.finos.scan.github.client.Topic;
import org.finos.scan.github.client.util.QueryExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.graphql_java_generator.exception.GraphQLRequestExecutionException;
import com.graphql_java_generator.exception.GraphQLRequestPreparationException;

@Service
public class QueryService {
	
	public static final Logger QUERY_LOGGER = LoggerFactory.getLogger(QueryService.class);
	
	@Autowired
	QueryExecutor qe;
	
	public <X> X getSingleRepository(QueryType<X> qt, String owner, String name) throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		Repository r = getRawRepository(qt, owner, name);
		return qt.convert(r, qe);
	}
	
	public <X> Repository getRawRepository(QueryType<X> qt, String owner, String name) throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		String query = "{\n"
				+ "    id\n"
				+ "    name\n"
				+ "    owner\n"				
				+ "          "+qt.getFields()+"\n"
				+ "}";
		
		Repository r = qe.repository(query, true, name, owner);
		return r;
	}
	
	
	public <X> Map<String, X> getAllRepositoriesInTopic(QueryType<X> qt, String topic) throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		List<Repository> out = new ArrayList<Repository>();
		int total = 1000;
		String cursor = null;
		String query = buildQuery(qt);
		
		QUERY_LOGGER.info(query);
		
		while (total > out.size() && (out.size() < qt.getMaxRepositories())) {
			Topic o = qe.topic(query, topic, "cursor", cursor);
			
			RepositoryConnection conn = o.getRepositories();
		
			out.addAll(
				conn.getEdges().stream()
					.map(e -> e.getNode())
					.collect(Collectors.toList()));
			total = conn.getTotalCount();
			cursor = conn.getPageInfo().getEndCursor();
		}
		
		if (out.size() > qt.getMaxRepositories()) {
			out.subList(0, qt.getMaxRepositories()).clear();
		}
		
		return out.stream().collect(Collectors.toMap(
				r -> r.getName(), 
				r-> qt.convert(r, qe),
				(a,b) -> a));	// deal with dups
	}
	
	public <X> Map<String, X> getAllRepositoriesInOrg(QueryType<X> qt, String org) throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		List<Repository> out = new ArrayList<Repository>();
		int total = 1000;
		String cursor = null;
		String query = buildQuery(qt);
		
		QUERY_LOGGER.info(query);
		
		while (total > out.size()) {
			Organization o = qe.organization(query, org, "cursor", cursor);
			
			RepositoryConnection conn = o.getRepositories();
			out.addAll(
				conn.getEdges().stream()
					.map(e -> e.getNode())
					.collect(Collectors.toList()));
			total = conn.getTotalCount();
			cursor = conn.getPageInfo().getEndCursor();
			try {
				Thread.sleep(5000);
			} catch (InterruptedException e1) {
				e1.printStackTrace();
			}
		}
		
		return out.stream().collect(Collectors.toMap(r -> r.getOwner().getLogin()+","+r.getName(), r-> qt.convert(r, qe)));
				
	}

	private <X> String buildQuery(QueryType<X> qt) {
		return "{\n"
				+ "    id\n"
				+ "    repositories("+qt.getRepositoryQueryPrefix()+"first: "+qt.getPageSize()+", after: &cursor) { \n"
				+ "      totalCount\n"
				+ "      totalDiskUsage\n"
				+ "      pageInfo {\n"
				+ "        endCursor\n"
				+ "        startCursor\n"
				+ "      }\n"
				+ "      edges {\n"
				+ "        node {\n"
				+ "          name \n"
				+ "          owner \n"
				+ "          "+qt.getFields()
				+ "        }\n"
				+ "      }\n"
				+ "    }\n"
				+ "  }\n"
				+ "}";
	}
}
