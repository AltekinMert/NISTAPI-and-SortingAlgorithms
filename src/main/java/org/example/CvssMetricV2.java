package org.example;

public class CvssMetricV2 {
    private String source;
    private String type;
    public CvssData cvssData;
    private String baseSeverity;
    public double exploitabilityScore;
    public double impactScore;
    private boolean acInsufInfo;
    private boolean obtainAllPrivilege;
    private boolean obtainUserPrivilege;
    private boolean obtainOtherPrivilege;
    private boolean userInteractionRequired;
}