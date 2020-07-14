/**
 * $Project (c) Bug Busters Security Team 2020
 */
package bbst;

import com.google.gson.annotations.SerializedName;

public class SECRTshModel {
    @SerializedName("name_value")
    protected final String name_value;

    public SECRTshModel(String name_value) {
        this.name_value = name_value;
    }
}
