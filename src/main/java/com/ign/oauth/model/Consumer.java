package com.ign.oauth.model;

import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Id;
import javax.persistence.Column;
import java.io.Serializable;

@Entity
@Table(name = "OAUTH_CONSUMER")
public class Consumer implements Serializable {
    private String consName;
    private String consSecret;
    private String consRSAKey;
    private String consKey;

    @Column(name = "CONS_NAME")
    public String getConsName() {
        return consName;
    }

    public void setConsName(String consName) {
        this.consName = consName;
    }

    @Column(name = "CONS_SECRET")
    public String getConsSecret() {
        return consSecret;
    }

    public void setConsSecret(String consSecret) {
        this.consSecret = consSecret;
    }

    @Id
    @Column(name = "CONS_KEY")
    public String getConsKey() {
        return consKey;
    }

    public void setConsKey(String consKey) {
        this.consKey = consKey;
    }

    @Column(name = "CONS_RSAKEY")
    public String getConsRSAKey() {
        return consRSAKey;
    }

    public void setConsRSAKey(String consRSAKey) {
        this.consRSAKey = consRSAKey;
    }
}
