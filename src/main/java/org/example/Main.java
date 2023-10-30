package org.example;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Collections;

import com.google.gson.Gson;
public class Main {
    public static void mergeSort(List<CVEVulnerability> list) {
        if (list == null || list.size() <= 1) {
            return; // Nothing to sort
        }

        List<CVEVulnerability> temp = new ArrayList<>(list);
        mergeSort(list, temp, 0, list.size() - 1);
    }
    private static void mergeSort(List<CVEVulnerability> list, List<CVEVulnerability> temp, int left, int right) {
        if (left < right) {
            int middle = (left + right) / 2;

            // Sort the left and right halves
            mergeSort(list, temp, left, middle);
            mergeSort(list, temp, middle + 1, right);

            // Merge the sorted halves
            merge(list, temp, left, middle, right);
        }
    }
    private static void merge(List<CVEVulnerability> list, List<CVEVulnerability> temp, int left, int middle, int right) {
        // Copy data to temporary lists
        for (int i = left; i <= right; i++) {
            temp.set(i, list.get(i));
        }

        int i = left;
        int j = middle + 1;
        int k = left;

        // Merge the two halves back into the original list
        while (i <= middle && j <= right) {
            if (temp.get(i).compareTo(temp.get(j)) <= 0) {
                list.set(k, temp.get(i));
                i++;
            } else {
                list.set(k, temp.get(j));
                j++;
            }
            k++;
        }

        // Copy any remaining elements from the left half
        while (i <= middle) {
            list.set(k, temp.get(i));
            k++;
            i++;
        }
    }


    public static void main(String[] args){
        String baseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
        List<CVEVulnerability> EveryEntry = new ArrayList<>();
        int resultsPerPage = 2000;
        int totalEntries = 4000;
        int a = 0;
        double baseScore = 0;
        double impactScore = 0;
        double exploitabilityScore = 0;
        Gson gson = new Gson();

        for (int startIndex = 0; startIndex < totalEntries; startIndex += resultsPerPage) {
            try {
                // Create the URL for the current page
                String url = baseUrl + "/?resultsPerPage=" + resultsPerPage + "&startIndex=" + startIndex;
                HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
                connection.setRequestMethod("GET");

                // Get the response
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String line;
                StringBuilder response = new StringBuilder();
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();
                connection.disconnect();

                // Parse the JSON response into Java objects
                String jsonResponse = response.toString();
                CVEData cveData = gson.fromJson(jsonResponse, CVEData.class);

                EveryEntry.addAll(cveData.vulnerabilities);

                // Access and process the parsed data
                System.out.println("CVE ID: " + cveData.vulnerabilities.get(2).cve.id);
                System.out.println("baseScore: "+cveData.vulnerabilities.get(2).cve.metrics.cvssMetricV2.get(0).cvssData.baseScore);
                System.out.println("ImpactScore: "+cveData.vulnerabilities.get(2).cve.metrics.cvssMetricV2.get(0).impactScore);
                System.out.println("ExploitabilityScore: "+cveData.vulnerabilities.get(2).cve.metrics.cvssMetricV2.get(0).exploitabilityScore);
                // Access other fields as needed

            } catch (IOException e) {
                e.printStackTrace();
            }

        }
        long startTime = System.nanoTime();
        mergeSort(EveryEntry);
        long endTime = System.nanoTime();
        long executionTime = endTime -startTime;
        System.out.println("Merge Sort Execution Time: " + executionTime+ "nanoseconds");
        Iterator<CVEVulnerability> iterator = EveryEntry.iterator();
        while (iterator.hasNext()) {
            CVEVulnerability vulnerability = iterator.next();
            if(vulnerability.cve.metrics.cvssMetricV2 != null){
                baseScore = vulnerability.cve.metrics.cvssMetricV2.get(0).cvssData.baseScore;
            }
            if(vulnerability.cve.metrics.cvssMetricV2 != null){
                impactScore = vulnerability.cve.metrics.cvssMetricV2.get(0).impactScore;
            }
            if(vulnerability.cve.metrics.cvssMetricV2 != null){
                exploitabilityScore = vulnerability.cve.metrics.cvssMetricV2.get(0).exploitabilityScore;
            }
            System.out.println("baseScore: " + baseScore+ ", impactScore: " + impactScore + ", exploitabilityScore: "+exploitabilityScore+", CVEId: "+ vulnerability.cve.id);
            a++;
        }
    }
}