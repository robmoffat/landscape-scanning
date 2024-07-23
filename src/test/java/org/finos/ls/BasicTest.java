package org.finos.ls;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import org.finos.ls.landscape.ProjectInfo;
import org.finos.ls.outputs.CommitService;
import org.finos.ls.outputs.PullRequestService;
import org.finos.ls.queries.Activity;
import org.finos.ls.queries.BasicQueries;
import org.finos.ls.queries.BasicQueries.FinosStage;
import org.finos.ls.queries.BasicQueries.OpenSSFStatus;
import org.finos.ls.queries.MarkdownSummarizer;
import org.finos.ls.queries.MarkdownSummarizer.SummaryLevel;
import org.finos.ls.readme.ReadmeGenerator;
import org.finos.ls.queries.ProjectScanCSVSummarizer;
import org.finos.scan.github.client.Repository;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import com.graphql_java_generator.exception.GraphQLRequestExecutionException;
import com.graphql_java_generator.exception.GraphQLRequestPreparationException;

@SpringBootTest(classes = AnalysisApp.class)
@ActiveProfiles("local")
public class BasicTest {
	
	private static final String ORG = "finos";
	private static final String ORG2 = "finos-labs";

	
	@Autowired
	QueryService qs;
	
	@Autowired
	CommitService cs;
	
	@Autowired
	PullRequestService pr;
	
	@Autowired
	ReadmeGenerator readme;
	
	@Autowired
	CSVGenerator csv;

	@Test
	public void testSingleRepo() throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		Repository repo = qs.getSingleRepository(BasicQueries.PASSTHROUGH, ORG, "spring-bot");
		Assertions.assertEquals(ORG, repo.getOwner().getLogin());
		Assertions.assertEquals("spring-bot", repo.getName());
	}

	@Test
	public void testRepoDownloadViaOrganisation() throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {		
		Map<String, Repository> allRepos = qs.getAllRepositoriesInOrg(BasicQueries.PASSTHROUGH, ORG);
		
		Repository firstRepo = allRepos.get("OpenMAMA");
		Assertions.assertEquals("OpenMAMA", firstRepo.getName());
		
		// ok, can we pull back the entire list of repositories?
		for (Repository re : allRepos.values()) {
			System.out.println(re.getName());
		}
	}
	
	@Test
	public void testListOfReposWithLicenseInfo() throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		Map<String, String> licenseDetails = qs.getAllRepositoriesInOrg(BasicQueries.LICENSE_INFO, ORG);
		outputMap(licenseDetails);
		Assertions.assertTrue(licenseDetails.size() > 110);
	}
	
	public <X> long countStatus(Map<String, X> input, X expected) {
		return input.entrySet().stream()
			.filter(e -> e.getValue().equals(expected))
			.count();
	}
	
	@Test
	public void testListOfReposWithStatusInfo() throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		FinosStage status = qs.getSingleRepository(BasicQueries.FINOS_STAGE, ORG, "FDC3");
		Assertions.assertEquals(FinosStage.ACTIVE, status);
		
		status = qs.getSingleRepository(BasicQueries.FINOS_STAGE, ORG, "spring-bot");
		Assertions.assertEquals(FinosStage.INCUBATING, status);
		
		status = qs.getSingleRepository(BasicQueries.FINOS_STAGE, ORG, "datahub");
		Assertions.assertEquals(FinosStage.NONE, status);
		
		Map<String, FinosStage> statuses = qs.getAllRepositoriesInOrg(BasicQueries.FINOS_STAGE, ORG);
		outputMap(statuses);

		Assertions.assertTrue(countStatus(statuses, FinosStage.ACTIVE)>5);
		Assertions.assertTrue(countStatus(statuses, FinosStage.INCUBATING)>5);
		
	
	}
	
	
	@Test
	public void testOpenSSFStatus() throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		OpenSSFStatus status = qs.getSingleRepository(BasicQueries.OPENSSF_STATUS, ORG, "OpenMAMA");
		Assertions.assertEquals(OpenSSFStatus.NONE, status);
		
		status = qs.getSingleRepository(BasicQueries.OPENSSF_STATUS, ORG, "spring-bot");
		Assertions.assertEquals(OpenSSFStatus.OK, status);
		
		Map<String, OpenSSFStatus> statuses = qs.getAllRepositoriesInOrg(BasicQueries.OPENSSF_STATUS, ORG);
		outputMap(statuses);
		Assertions.assertTrue(countStatus(statuses, OpenSSFStatus.OK)>0);
		Assertions.assertTrue(countStatus(statuses, OpenSSFStatus.NONE)>5);

	}
	
	@Test
	public void testMainBranchReviewers() throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		Map<String, Integer> reviewers = qs.getAllRepositoriesInOrg(BasicQueries.BRANCH_RULES, ORG);
		outputMap(reviewers);
		Assertions.assertTrue(reviewers.size() > 110);
	}
	
	@Test
	public void testRecentCommitterDetails() throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		Map<String, Activity> committers = qs.getAllRepositoriesInOrg(BasicQueries.MAIN_RECENT_COMMITTERS, ORG);
		outputMap(committers);
		Assertions.assertTrue(committers.size() > 110);
	}
	
	@Test
	public void testAdminDetails() throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		String admins = qs.getSingleRepository(BasicQueries.WRONG_ADMINS, "robmoffat", "landscape-scanning");
		System.out.println(admins);
		Assertions.assertEquals("@robmoffat", admins);
	}
	
	@Test
	public void testCVEScanningDetails() throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		Map<String, Boolean> cve = qs.getAllRepositoriesInOrg(BasicQueries.CVE_SCANNING_ACTION, ORG);
		outputMap(cve);
		Assertions.assertTrue(cve.size() > 110);
		Assertions.assertTrue(cve.get("electron-fdc3"));
	}
	
	@Test
	public void testSemgrepDetails() throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		Map<String, Boolean> semgrep = qs.getAllRepositoriesInOrg(BasicQueries.SEMGREP_ACTION, ORG);
		outputMap(semgrep);
		Assertions.assertTrue(semgrep.size() > 110);
		Assertions.assertTrue(semgrep.get("electron-fdc3"));
	}
	
	@Test
	public void testRecentIssueActivity() throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		Map<String, Activity> activity = qs.getAllRepositoriesInOrg(BasicQueries.ISSUE_ACTIVITY, ORG);
		outputMap(activity);
		Assertions.assertTrue(activity.size() > 110);
	}

	private void outputMap(Map<String, ? extends Object> licenseDetails) {
		licenseDetails.entrySet().stream()
			.forEach(e -> System.out.println(e.getKey()+ " "+e.getValue()));
	}
	
	@Test
	public void testSummaryGenerationMain() throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		ProjectInfo pi = new ProjectInfo();
		pi.category = "Platforms and Runtimes";
		pi.subcategory = "Interop";
		pi.name = "Spring Bot";
		pi.logo = "https://raw.githubusercontent.com/finos/finos-landscape/master/hosted_logos/springbot.svg";
		pi.homepageUrl = "https://springbot.finos.org";
		pi.type = org.finos.ls.landscape.ProjectInfo.ProjectType.ACTIVE;
		String out = qs.getSingleRepository(new MarkdownSummarizer(SummaryLevel.MAIN, pi), ORG, "spring-bot");
		System.out.println(out);
	}
	
	@Test
	public void testBadReadme() throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		String out = qs.getSingleRepository(new MarkdownSummarizer(SummaryLevel.SUBITEM, new ProjectInfo()), ORG, "symphonyelectron");
		System.out.println(out);
	}
	
	@Test
	public void testWholeReadme() throws Exception {
		String out = readme.generateInner();
		System.out.println(out);
	}
	
	@Test
	public void testDifferentlyNamedReadme() throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		String out = qs.getSingleRepository(new MarkdownSummarizer(SummaryLevel.SUBITEM, new ProjectInfo()), ORG, "kdb-studio");
		System.out.println(out);
	}
	
	@Test
	public void testCSV() throws Exception {
		String out = csv.generateOrg(ORG, new ProjectScanCSVSummarizer(Collections.emptyList()));
		System.out.println(out);
	}
	
	@Test
	public void testCommit() throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		cs.commitFile("somefile.md", "This is some contents".getBytes(), "generated-branch", "landscape-scanning", "robmoffat");
	}
	
	@Test
	public void testPR() throws GraphQLRequestExecutionException, GraphQLRequestPreparationException {
		pr.createOrUpdatePullRequest("landscape-scanning", "robmoffat", "main", "generated-branch",Arrays.asList("@robmoffat"), "Get this merged");
		pr.createOrUpdatePullRequest("landscape-scanning", "robmoffat", "main", "generated-branch",Arrays.asList("@robmoffat"), "new comment");
		pr.closePullRequest("landscape-scanning", "robmoffat", "main", "generated-branch");
	}
	
}
