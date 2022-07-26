package org.finos.ls;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.finos.ls.queries.Activity;
import org.finos.ls.queries.BasicQueries;
import org.finos.ls.queries.MarkdownSummarizer;
import org.finos.ls.queries.MarkdownSummarizer.SummaryLevel;
import org.finos.scan.github.client.Repository;
import org.finos.scan.github.client.util.QueryExecutor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.graphql_java_generator.exception.GraphQLRequestExecutionException;
import com.graphql_java_generator.exception.GraphQLRequestPreparationException;

@Service
public class ReadmeGenerator {

	@Autowired
	QueryService qs;
	
	@Autowired 
	QueryExecutor qe;
	
	Map<String, Repository> cache = new HashMap<>();
	
	public String generate(int cutoff, String org) throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		Map<String, Activity> activeProjects = qs.getAllRepositoriesInOrg(BasicQueries.COMBINED_ACTIVITY, org);
		
		List<String> names = activeProjects.entrySet().stream()
			.filter(r -> r.getValue().getScore() > cutoff)
			.sorted((a, b) -> ((Long) b.getValue().getScore()).compareTo(a.getValue().getScore()))
			.map(e -> e.getKey().toLowerCase())
			.collect(Collectors.toList());
		
		StringBuilder out = new StringBuilder();
		out.append("# FINOS Projects\n\n");
		String date = new SimpleDateFormat("dd MMM yyyy").format(new Date());
		out.append("Here are some of FINOS' most active projects (as of "+date+"):\n\n");
		
		Map<String, List<String>> bucketedProjects = bucketNames(names);
		
		out.append(tableOfContents(bucketedProjects));
		
		out.append(report(bucketedProjects));
		
		out.append("\n\n_For the full list see the repositories below_\n");
		return out.toString();
	}

	private String tableOfContents(Map<String, List<String>> bucketedProjects) throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		StringBuilder out = new StringBuilder();
		bucketedProjects.entrySet().stream()
			.sorted((a, b) -> a.getKey().compareToIgnoreCase(b.getKey()))
			.forEach(entry -> {
				String key = entry.getKey();
				List<String> val = entry.getValue();
				Collections.sort(val);
				if (val.size() == 1) {
					String string = getTitleForRepo(val.get(0));
					out.append(" - ["+string+"](#"+string.replace(" ", "-")+")\n");
				} else {
					out.append(" - "+key+"\n");
					for (String string : val) {
						String title = getTitleForRepo(string);
						out.append("   - ["+title+"](#"+title.replace(" ", "-")+")\n");
					}
				}
		});
		
		return out.toString();
	}

	private String getTitleForRepo(String name) {
		try {
			MarkdownSummarizer s = new MarkdownSummarizer(SummaryLevel.SUBITEM);
			Repository repo = getRepoDetails(s, name);
			String title = s.getTitleFromNameOrH1(name, repo);
			return title;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private String report(Map<String, List<String>> bucketedProjects) {
		MarkdownSummarizer topLevel = new MarkdownSummarizer(SummaryLevel.MAIN);
		MarkdownSummarizer secondLevel = new MarkdownSummarizer(SummaryLevel.SUBITEM);
		StringBuilder out = new StringBuilder();
		bucketedProjects.entrySet().stream()
			.sorted((a, b) -> a.getKey().compareToIgnoreCase(b.getKey()))
			.forEach(e -> {
				List<String> items = e.getValue();
				Collections.sort(items);
				if (items.size() > 1) {
					out.append("## "+e.getKey()+"\n\n");
					items.forEach(i -> appendUsing(secondLevel, i, out));
				} else {
					appendUsing(topLevel, items.get(0), out);
				}
			});
		
		return out.toString();
	}

	private void appendUsing(MarkdownSummarizer l, String name, StringBuilder out) {
		try {
			out.append(l.convert(getRepoDetails(l, name), qe));
		} catch (Exception e) {
			throw new RuntimeException("Couldn't process: ", e);
		}
	}

	private Repository getRepoDetails(MarkdownSummarizer l, String name)
			throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		
		if (!cache.containsKey(name)) {
			cache.put(name, qs.getRawRepository(l, "finos", name));
		}
			
		return cache.get(name);
	}

	private Map<String, List<String>> bucketNames(List<String> names) {
		Map<String, List<String>> out = new HashMap<String, List<String>>();
		names = remove(names, n -> n.contains("juju"));
		names = bucket(out, names, "Legend", n -> n.contains("legend"));
		names = bucket(out, names, "Morphir", n -> n.contains("morphir"));
		names = bucket(out, names, "Symphony", n -> n.contains("symphony"));
		names = bucket(out, names, "FDC3", n -> n.contains("fdc3"));
		names = bucket(out, names, "Waltz", n -> n.contains("waltz"));
		names = remove(names, 
				"finos-landscape", 
				"software-project-blueprint", 
				"standards-project-blueprint", 
				"clabot-config",
				"finos-parent-pom");
		names = bucketItems(out, names, "Symphony", "messageml-utils");
		names = bucketItems(out, names, "SIGs", "dei-sig", "innersource", "curref-data", "open-source-readiness", "compliant-financial-infrastructure");
		singleBucketTheRest(out, names);
		return out;
	}

	private void singleBucketTheRest(Map<String, List<String>> out, List<String> names) {
		names.stream()
			.forEach(n -> out.put(n, Collections.singletonList(n)));
	}

	private List<String> remove(List<String> items, String... toRemove) {
		List<String> toGo = Arrays.asList(toRemove);
		return remove(items, n -> toGo.contains(n));
	}
	
	private List<String> remove(List<String> items, Predicate<String> toRemove) {
		return items.stream()
				.filter(n -> !toRemove.test(n))
				.collect(Collectors.toList());
	}
	
	private List<String> bucketItems(Map<String, List<String>> out, List<String> in, String key, String... toInclude) {
		List<String> toGo = Arrays.asList(toInclude);
		return bucket(out, in, key, n -> toGo.indexOf(n) > -1);
	}

	private List<String> bucket(Map<String, List<String>> out, List<String> in, String key, Predicate<String> test) {
		return in.stream()
			.map(n -> { 
				if (test.test(n)) {
					List<String> names = out.getOrDefault(key, new ArrayList<>());
					names.add(n);
					out.put(key, names);
				}
				return n;
			})
			.filter(test.negate())
			.collect(Collectors.toList());
	}
}
