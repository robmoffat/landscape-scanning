package org.finos.ls.queries;

import java.util.ArrayList;
import java.util.List;

import org.finos.ls.landscape.ProjectInfo;
import org.finos.ls.landscape.ProjectInfo.ProjectType;
import org.finos.ls.queries.BasicQueries.FinosStage;
import org.finos.ls.queries.BasicQueries.OpenSSFStatus;
import org.finos.scan.github.client.Repository;
import org.finos.scan.github.client.util.QueryExecutor;
import org.springframework.util.StringUtils;

public class ProjectScanCSVSummarizer implements CSVSummarizer{
	
	private List<ProjectInfo> projects;

	public ProjectScanCSVSummarizer(List<ProjectInfo> projects) {
		super();
		this.projects = projects;
	}
	
	public static final String[] FIELDS = {
		"Score",
		"Organisation",
		"Repo Name",
		"Project Name",
		"Project Type",
		"Project Stage",
		"Stage",
		"Github Archived",
		"License",
		"Meeting Attendance",
		"Issue/PR Activity",
		"Commit Activity",
		"OpenSSF Best Practices",
		"Branch Protection",
		"SemGrep",
		"CVE Scanning",
		"Default Branch Name",
		"Admins",
		"Issue Participants",
		"Committers",
		"Readme Length",
	};

	@Override
	public String getFields() {
		// could do with a more solid way of merging these things
		
		return  BasicQueries.BRANCH_RULES_QUERY+" "+
				BasicQueries.PASSTHROUGH.getFields() + " " + 
				BasicQueries.COMBINED_ACTIVITY.getFields() + " " + 
				BasicQueries.OPENSSF_STATUS.getFields() + " " +
				BasicQueries.WRONG_ADMINS.getFields() + " " +
				BasicQueries.LICENSE_INFO.getFields();
	}

	@Override
	public List<Object> convert(Repository r, QueryExecutor qe) {

		// TODO - make sure PRs are included
		Activity issue = BasicQueries.ISSUE_ACTIVITY.convert(r, qe);

		// TODO - remove 100 items cap
		Activity commit = BasicQueries.MAIN_RECENT_COMMITTERS.convert(r, qe);

		// TODO - build query
		Activity meetingAttendance = null;
		FinosStage finosStage = BasicQueries.FINOS_STAGE.convert(r, qe);
		OpenSSFStatus openSSF = BasicQueries.OPENSSF_STATUS.convert(r, qe);
		String license = BasicQueries.LICENSE_INFO.convert(r, qe);

		Boolean semGrep = BasicQueries.SEMGREP_ACTION.convert(r, qe);
		Boolean cveScan = BasicQueries.CVE_SCANNING_ACTION.convert(r, qe);
		String defaultBranchName = BasicQueries.DEFAULT_BRANCH_NAME.convert(r, qe);
		String wrongAdmins = BasicQueries.WRONG_ADMINS.convert(r, qe);
		int branchReviewers = BasicQueries.BRANCH_RULES.convert(r, qe);
		long score = calculateScore(issue, commit, r.getName(), r.getIsPrivate() | r.getIsArchived());
		// TODO - this may be useful for documenting health criteria
		// String pass = passes(finosStatus, openSSF, wrongAdmins, branchReviewers, license, semGrep, cveScan, score == -1);
		long readmeLength = BasicQueries.README_LENGTH.convert(r, qe);
		
		List<Object> out = new ArrayList<>();
		out.add(score);
		out.add(r.getOwner().getLogin());
		out.add(r.getName());
		out.add(projectName(r));
		out.add(projectType(r));
		out.add(projectStage(r));
		out.add(finosStage.name());
		out.add(r.getIsArchived());
		out.add(license);
		out.add(meetingAttendance);
		out.add(issue.getScore());
		out.add(commit.getScore());
		out.add(openSSF.name());
		out.add(r.getIsPrivate() ? "PRIVATE" : ""+branchReviewers);
		out.add(semGrep);
		out.add(cveScan);
		out.add(defaultBranchName);
		out.add(wrongAdmins);
		out.add(convertToSpaceList(issue));
		out.add(convertToSpaceList(commit));
		out.add(readmeLength);
		return out;
	}

	private String projectName(Repository r) {
		ProjectInfo pi = getMatchingProject(r.getName(), r.getOwner().getLogin());
		return pi != null ? pi.name : "";
	}
	
	private String projectType(Repository r) {
		ProjectInfo pi = getMatchingProject(r.getName(), r.getOwner().getLogin());
		return (pi != null) && pi.type == ProjectType.SIG ? "SIG" : "Project";
	}
	
	private String projectStage(Repository r) {
		ProjectInfo pi = getMatchingProject(r.getName(), r.getOwner().getLogin());
		return (pi != null) && pi.type == ProjectType.INCUBATING ? "Incubating" : "Active";
	}
	
	private boolean matchName(String name, String owner, String url) {
		return (url != null) && url.toLowerCase().contains("/"+name.toLowerCase()) && url.contains("/"+owner.toLowerCase()+"/");
	}

	private ProjectInfo getMatchingProject(String name, String owner) {
		for (ProjectInfo projectInfo : projects) {
			if (matchName(name, owner, projectInfo.mainRepo)) {
				return projectInfo;
			}
			
			if (projectInfo.additionalRepos != null) {
				for (String string : projectInfo.additionalRepos) {
					if (matchName(name, owner, string)) {
						return projectInfo;
					}
				}
			}
		}
		
		return null;
	}

	private String passes(FinosStage finosStatus, OpenSSFStatus openSSFStatus, String wrongAdmins, int branchReviewers, String license, boolean semGrep, Boolean cveScan, boolean ignore) {
		StringBuilder sb = new StringBuilder();
		
		if (ignore) {
			return "";
		} 
		
		if ((finosStatus == FinosStage.NONE) || (finosStatus == FinosStage.NO_README)) {
			sb.append(" (Finos Lifecycle)");
		}
		
		if (wrongAdmins.length() > 0) { 
			sb.append(" (wrong admins)");
		}
		
		if ((openSSFStatus == OpenSSFStatus.NONE) || (openSSFStatus == OpenSSFStatus.NO_README)) {
			sb.append(" (OpenSSF Status)");
		}
		
		if (branchReviewers == -1) {
			sb.append(" (Branch Reviewers)");
		}
		
		if (!StringUtils.hasLength(license)) {
			sb.append(" (No License Set)");
		}
		
		if (isSoftwareLicense(license)) {
			if (!cveScan) {
				sb.append(" (No CVE Scan)");				
			}
			if (!semGrep) {
				sb.append(" (No Sem Grep)");				
			}
		}
		
		if (sb.length() > 0) { 
			return "FAIL"+sb.toString();
		} else {
			return "";
		}
		
  	}

	private boolean isSoftwareLicense(String license) {
		return !"CC-BY-4.0".equals(license);
	}

	private long calculateScore(Activity issue, Activity commit, String name, boolean ignore) {
		return ignore ? -1 : (issue.getScore() + commit.getScore());
	}

	private String convertToSpaceList(Activity issue) {
		return issue.getPeople().stream().reduce((a, b) -> a+" "+b).orElse("");
	}

	@Override
	public int getPageSize() {
		return 2;
	}

	@Override
	public String[] getColumnNames() {
		return FIELDS;
	}

}
