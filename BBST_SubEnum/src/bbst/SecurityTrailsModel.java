/**
 * $Project (c) Bug Busters Security Team 2020
 */
package bbst;

import com.google.gson.annotations.SerializedName;

import java.util.List;

public class SecurityTrailsModel {
    @SerializedName("subdomains")
    protected final List<String> subdomains;

    public SecurityTrailsModel(List<String> subdomains) {
        this.subdomains = subdomains;
    }
}