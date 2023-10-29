package org.example;

import java.util.List;

public class CVEData {
    public int resultsPerPage;
    public int startIndex;
    public int totalResults;
    public String format;
    public String version;
    public String timestamp;
    public List<CVEVulnerability> vulnerabilities;
}