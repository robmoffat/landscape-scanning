package org.finos.ls.queries;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.finos.scan.github.client.Blob;
import org.finos.scan.github.client.BranchProtectionRule;
import org.finos.scan.github.client.BranchProtectionRuleConnection;
import org.finos.scan.github.client.Commit;
import org.finos.scan.github.client.Issue;
import org.finos.scan.github.client.IssueComment;
import org.finos.scan.github.client.License;
import org.finos.scan.github.client.Organization;
import org.finos.scan.github.client.Ref;
import org.finos.scan.github.client.Repository;
import org.finos.scan.github.client.RepositoryCollaboratorEdge;
import org.finos.scan.github.client.RepositoryPermission;
import org.finos.scan.github.client.Tree;
import org.finos.scan.github.client.TreeEntry;
import org.finos.scan.github.client.util.QueryExecutor;

public class BasicQueries {

	public static final String NO_FIELDS = "";
	
	public static final String FILE_LIST = "object(expression: \"HEAD:\") {\n"
			+ "        ... on Tree {\n"
			+ "          id\n"
			+ "          entries {\n"
			+ "            path\n"
			+ "          }\n"
			+ "        }\n"
			+ "      }";

	public enum FinosStage { NO_README, INCUBATING, ACTIVE, NONE }

	public enum OpenSSFStatus { NO_README, OK, NONE }
	
	public static QueryType<Repository> PASSTHROUGH = new AbstractQueryType<Repository>(
			NO_FIELDS, 50, (r, qe) -> r);
	
	public static final String BRANCH_RULES_QUERY = 
			  "    branchProtectionRules(first: 10) {\n"
			+ "      edges {\n"
			+ "        node {\n"
			+ "          id\n"
			+ "          requiredApprovingReviewCount\n"
			+ "          requiredStatusCheckContexts\n"
			+ "          requiresApprovingReviews\n"
			+ "          requiresCodeOwnerReviews\n"
			+ "          requiresCommitSignatures\n"
			+ "          requiresConversationResolution\n"
			+ "          requiresLinearHistory\n"
			+ "          requiresStatusChecks\n"
			+ "          requiresStrictStatusChecks\n"
			+ "          restrictsPushes\n"
			+ "          restrictsReviewDismissals\n"
			+ "          pattern\n"
			+ "        }\n"
			+ "      }\n"
			+ "    }\n";
	
	public static QueryType<Integer> BRANCH_RULES = new AbstractQueryType<>("   defaultBranchRef {\n"
			+ "      id\n"
			+ "      name\n"
			+ "    }\n"
			+ BRANCH_RULES_QUERY, 20, (r, qe) -> convertToRuleSummary(r));
	
	public static QueryType<String> DEFAULT_BRANCH_NAME = new AbstractQueryType<>("   defaultBranchRef {\n"
			+ "      id\n"
			+ "      name\n"
			+ "    }\n"
			, 20, (r, qe) -> r.getDefaultBranchRef().getName());
	
	
	public static QueryType<String> WRONG_ADMINS = new AbstractQueryType<>("collaborators(first: 100) {\n"
			+ "          edges {\n"
			+ "            permission\n"
			+ "            node {\n"
			+ "              login\n"
			+ "            }\n"
			+ "          }\n"
			+ "        }", 20, (r, qe) -> wrongAdmins(r));
	
	
	public static QueryType<FinosStage> FINOS_STAGE = new AbstractQueryType<FinosStage>(	
			FILE_LIST, 10, (r, qe) -> {
			
			String text = getReadme(r, qe);
			if (text == null) {
				return FinosStage.NO_README;
			} else if (text.contains("https://finosfoundation.atlassian.net/wiki/display/FINOS/Incubating") || 
					text.contains("https://cdn.jsdelivr.net/gh/finos/contrib-toolbox@master/images/badge-incubating.svg")) {
				return FinosStage.INCUBATING;
			} else if (text.contains("https://finosfoundation.atlassian.net/wiki/display/FINOS/Active") ||
					text.contains("https://cdn.jsdelivr.net/gh/finos/contrib-toolbox@master/images/badge-released.svg")) {
				return FinosStage.ACTIVE;
			} else {
				return FinosStage.NONE;
			}
		});

	
	public static QueryType<Integer> README_LENGTH = new AbstractQueryType<Integer>(	
			FILE_LIST, 10, (r, qe) -> {
			
			String text = getReadme(r, qe);
			return text == null  ? 0 : text.length();
		});
	
	
	public static QueryType<Activity> ISSUE_ACTIVITY = new AbstractQueryType<>("issues(\n"
		+ "      orderBy: {field: UPDATED_AT, direction: DESC}\n"
		+ "      first: 50\n"
		+ "    ) {\n"
		+ "      edges {\n"
		+ "        node {\n"
		+ "          id\n"
		+ "          comments(first: 30) {\n"
		+ "            totalCount\n"
		+ "            edges {\n"
		+ "              node {\n"
		+ "                author {\n"
		+ "                  login\n"
		+ "                }\n"
		+ "                updatedAt\n"
		+ "              }\n"
		+ "            }\n"
		+ "          }\n"
		+ "          lastEditedAt\n"
		+ "          title\n"
		+ "        }\n"
		+ "      }\n"
		+ "    }", 5, (r, qe) -> condenseIssueCommenters(r));
	
	public static QueryType<Boolean> CVE_SCANNING_ACTION = new AbstractQueryType<Boolean>(NO_FIELDS, 50, (r, qe) -> fileContents(r,qe, ".github/workflows/cve-scanning.yml") != null);

	public static QueryType<Boolean> SEMGREP_ACTION = new AbstractQueryType<Boolean>(NO_FIELDS, 50, (r, qe) -> fileContents(r,qe, ".github/workflows/semgrep.yml") != null);
	
	public static QueryType<String> LICENSE_INFO = new AbstractQueryType<String>(" licenseInfo {\n"
		+ "            spdxId\n"
		+ "          }", 50, (r, qe) -> {
			License l = r.getLicenseInfo();
			return (l == null) ? "" : l.getSpdxId();});
	
	public static QueryType<Activity> MAIN_RECENT_COMMITTERS = new AbstractQueryType<>("defaultBranchRef {\n"
		+ "      id\n"
		+ "      name\n"
		+ "      target {\n"
		+ "        ... on Commit {\n"
		+ "          history(first: 100) {\n"
		+ "            edges {\n"
		+ "              node {\n"
		+ "                ... on Commit {\n"
		+ "                  committedDate\n"
		+ "                }\n"
		+ "                author {\n"
		+ "                  user {\n"
		+ "                    login\n"
		+ "                  }\n"
		+ "                }\n"
		+ "              }\n"
		+ "            }\n"
		+ "          }\n"
		+ "        }\n"
		+ "      }\n"
		+ "    }", 10, (r, qe) -> condenseRecentCommitters(r));
		
	
	public static QueryType<OpenSSFStatus> OPENSSF_STATUS = new AbstractQueryType<>(FILE_LIST, 20, (r, qe) -> {
		String text = getReadme(r, qe);
		if (text == null) {
			return OpenSSFStatus.NO_README;
		} else if (text.contains("https://bestpractices.coreinfrastructure.org")) {
			return OpenSSFStatus.OK;		
		} else {
			return OpenSSFStatus.NONE;
		}
	});
	
	public static final QueryType<Activity> COMBINED_ACTIVITY = new AbstractQueryType<>(
		BasicQueries.MAIN_RECENT_COMMITTERS.getFields() + 
		BasicQueries.ISSUE_ACTIVITY.getFields()+"  isArchived isPrivate",
		3,
		(r, qe) -> combinedActivity(r, qe));

	private static Activity combinedActivity(Repository r, QueryExecutor qe) {
		if (r.getIsArchived() || r.getIsPrivate()) {
			return new Activity(0, Collections.emptyList());
		} else {
			Activity a = BasicQueries.MAIN_RECENT_COMMITTERS.convert(r, qe);
			Activity b = BasicQueries.MAIN_RECENT_COMMITTERS.convert(r, qe);
			LinkedHashSet<String> combinedPeople = new LinkedHashSet<String>(a.getPeople());
			combinedPeople.addAll(b.getPeople());
			return new Activity(a.getScore() + b.getScore(), new ArrayList<>(combinedPeople));
		}
	}
	
	private static final Map<String, String> CACHED_README = new HashMap<String, String>();
	
	private static String wrongAdmins(Repository r) {
		StringBuilder out = new StringBuilder();
		for (RepositoryCollaboratorEdge rce : r.getCollaborators().getEdges()) {
			RepositoryPermission pe = rce.getPermission();
			if (pe == RepositoryPermission.ADMIN) {
				String userLogin = rce.getNode().getLogin();
				if (!okAdmin(userLogin)) {
					if (out.length() > 0) {
						out.append(", ");
					}
					out.append("@"+userLogin);
				}
			}
		}
		
		return out.toString();
	}

	private static boolean okAdmin(String userLogin) {
		return "thelinuxfoundation".equals(userLogin) || ("finos-admin".equals(userLogin));
	}
	
	private static String fileContents(Repository r, QueryExecutor qe, String name) {
		try {
			Organization o = qe.organization("{ repository(name: \""+r.getName()+"\") {\n"
					+ "        id\n"
					+ "        object(expression: \"HEAD:"+name+"\") {\n"
					+ "          ... on Blob {\n"
					+ "            text\n"
					+ "          }\n"
					+ "        }\n"
					+ "      }\n}", r.getOwner().getLogin());
			
			Blob blob = (Blob) o.getRepository().getObject();
			return blob == null ? null : blob.getText();
		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		} 
	}
	
	/**
	 * There are various different forms/cases the readme file can take:
	 * Readme.md, readme.md, README.rst, README.adoc
	 */
	private static String getReadme(Repository r, QueryExecutor qe) {
		String name = r.getName();
		String cached = CACHED_README.get(name);
		if (cached == null) {
			System.out.println("Getting readme for "+name);
			Tree tree = (Tree) r.getObject();
			if (tree != null) {
				for (TreeEntry e : tree.getEntries()) {
					if (e.getPath().toLowerCase().startsWith("readme")) {
						try {
							Organization o = qe.organization("{ repository(name: \""+name+"\") {\n"
									+ "        id\n"
									+ "        object(expression: \"HEAD:"+e.getPath()+"\") {\n"
									+ "          ... on Blob {\n"
									+ "            text\n"
									+ "          }\n"
									+ "        }\n"
									+ "      }\n}", r.getOwner().getLogin());
							cached = ((Blob) o.getRepository().getObject()).getText();
						} catch (Exception e1) {
							e1.printStackTrace();
						} 
						
					}
				}
			}
			
			CACHED_README.put(name, cached);	
		} else {
			System.out.println("Found in cache: "+name);
		}
				
		return cached;
	}
	
	private static Activity condenseIssueCommenters(Repository r) {
		Date cutoff = cutoff();
	
		Map<String, Long> comments = r.getIssues().getEdges().stream()
			.map(e -> e.getNode())
			.flatMap(n -> getComments(n))
			.filter(c -> cutoff.before(c.getUpdatedAt()))
			.collect(Collectors.groupingBy(c -> c.getAuthor().getLogin(), Collectors.counting()));
		
		return summarize(comments);
	}
	
	private static Activity condenseRecentCommitters(Repository r) {
		Date cutoff = cutoff();
		
		Ref defaultBranchRef = r.getDefaultBranchRef();
		if (defaultBranchRef == null) {
			return new Activity(0, Collections.emptyList());  // private repo or some security reason
		}
		Commit target = (Commit) defaultBranchRef.getTarget();
		Map<String, Long> counts = target.getHistory().getEdges().stream()
			.map(ce -> (Commit) ce.getNode())
			.filter(c -> cutoff.before(c.getCommittedDate()))
			.filter(c -> c.getAuthor().getUser() != null)
			.collect(Collectors.groupingBy(c -> c.getAuthor().getUser().getLogin(), Collectors.counting()));
		
		
		return summarize(counts);
	}
	
	private static Activity summarize(Map<String, Long> counts) {
		List<String> committers = counts.entrySet().stream()
			.sorted((a, b) -> -a.getValue().compareTo(b.getValue()))
			.map(e -> "@"+e.getKey())
			.collect(Collectors.toList());
		
		long totalCommitsInLastYear = counts.values().stream()
			.reduce(Long::sum)
			.orElse(0l);
		
		return new Activity(totalCommitsInLastYear,committers);
	}
	
	private static int countReviewers(BranchProtectionRule bpr) {
		if (bpr.getRequiresApprovingReviews()) {
			return bpr.getRequiredApprovingReviewCount();
		} else {
			return 0;
		}
	}
	
	private static Stream<IssueComment> getComments(Issue n) {
		return n.getComments().getEdges().stream()
			.map(e -> e.getNode());
	}
	
	private static boolean matches(BranchProtectionRule bpr, String mainBranch) {
		String pattern = bpr.getPattern();
		return mainBranch.matches(pattern.replaceAll("\\*",".*"));
	}
	
	private static Date cutoff() {
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.MONTH, -6);
		Date cutoff = cal.getTime();
		return cutoff;
	}
	
	public static int convertToRuleSummary(Repository r) {
		BranchProtectionRuleConnection bprc = r.getBranchProtectionRules();
		if (r.getDefaultBranchRef() == null) {
			return -1;
		}
		
		String mainBranch = r.getDefaultBranchRef().getName();
		return bprc.getEdges().stream()
			.map(e -> (BranchProtectionRule) e.getNode())
			.filter(bpr -> matches(bpr, mainBranch))
			.map(bpr -> countReviewers(bpr))
			.findFirst()
			.orElse(-1);
	}

}

