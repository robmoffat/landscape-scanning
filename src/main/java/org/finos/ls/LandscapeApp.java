package org.finos.ls;


import java.util.Arrays;
import java.util.Collections;

import org.finos.ls.queries.SecurityCSVSummarizer;
import org.finos.ls.search.FinanceCSVSummarizer;
import org.finos.scan.github.client.spring_autoconfiguration.SpringConfiguration;
import org.finos.scan.github.client.util.QueryExecutor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

import com.graphql_java_generator.client.GraphQLConfiguration;

@SpringBootApplication(scanBasePackageClasses = { LandscapeApp.class, GraphQLConfiguration.class, QueryExecutor.class, SpringConfiguration.class })
public class LandscapeApp implements CommandLineRunner {
	
	public static void main(String[] args) {
		SpringApplication.run(LandscapeApp.class, args);
	}

	@Autowired
	ReadmeGenerator readme;
	
	@Autowired
	CSVGenerator csv;
	
	@Autowired
	CommitService commit;
	
	@Autowired
	PullRequestService pr;
	
	@Value("${spring.profiles.active:}")
	String activeProfiles;
	
	@Value("${scanning.org:finos}")
	String org;
	
	@Value("${scanning.readme:README.md}")
	String readmeFile;
	
	@Value("${scanning.csv:scan.csv}")
	String csvFile;
	
	@Value("${scanning.finance.csv:finance-topic.csv}")
	String fcsvFile;
	
	@Value("${scanning.write-to.repo}")
	String repo;
	
	@Value("${scanning.write-to.owner}")
	String owner;

	@Value("${scanning.write-to.base}")
	String base;

	@Value("${scanning.write-to.head}")
	String head;
	
	@Value("${scanning.csv.priority:}")
	String[] priority;
	
	@Value("${scanning.csv.ignore:}")
	String[] ignore;

	@Autowired
	ConfigurableApplicationContext ctx;
	
	/**
	 * This method is started by Spring, once the Spring context has been loaded. This is run, as this class implements
	 * {@link CommandLineRunner}
	 */
	@Override
	public void run(String... args) throws Exception {
		if (activeProfiles.contains("summarize")) {
			// first, write the readme
			String readmeContent = readme.generate(25, org);
			commit.commitFile(readmeFile, readmeContent.getBytes(), head, repo, owner);
			
			// then write the csv
			SecurityCSVSummarizer summ = new SecurityCSVSummarizer(Arrays.asList(ignore), Arrays.asList(priority));
			String csvContent = csv.generateOrg(org, summ);
			commit.commitFile(csvFile, csvContent.getBytes(), head, repo, owner);
			
			FinanceCSVSummarizer fcsv = new FinanceCSVSummarizer();
			String fcsvContent = csv.generateTopic("finance", fcsv);
			commit.commitFile(fcsvFile, fcsvContent.getBytes(), head, repo, owner);
			
			// create a pr
			pr.createOrUpdatePullRequest(repo, owner, base, head, Collections.singletonList("@robmoffat"), "Updated Generated Files");
			ctx.close();
		}
	}
}