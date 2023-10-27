package org.example;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import com.google.gson.Gson;
public class Main {
    public static void main(String[] args){
        String baseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
        int resultsPerPage = 2000;
        int totalEntries = 4000;

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

                // Access and process the parsed data
                System.out.println("CVE ID: " + cveData.getVulnerabilities().get(1999).getCve().getId());
                // Access other fields as needed

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}