package org.example;
public class CvssData {
    private String version;
    private String vectorString;
    private String accessVector;
    private String accessComplexity;
    private String authentication;
    private String confidentialityImpact;
    private String integrityImpact;
    private String availabilityImpact;
    public double baseScore;
    private String baseSeverity;
    public double exploitabilityScore;
    public double impactScore;
    private boolean acInsufInfo;
    private boolean obtainAllPrivilege;
    private boolean obtainUserPrivilege;
    private boolean obtainOtherPrivilege;
    private boolean userInteractionRequired;
    // Add getters and setters
}
