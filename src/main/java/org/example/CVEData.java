package org.example;

import java.util.List;

public class CVEData {
    private int resultsPerPage;
    private int startIndex;
    private int totalResults;
    private String format;
    private String version;
    private String timestamp;
    private List<CVEVulnerability> vulnerabilities;
    public List<CVEVulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    // Getter and Setter methods
}