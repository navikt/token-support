package no.nav.security.spring.oidc.test;

/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.Charset;

import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.Resource;

import no.nav.security.oidc.configuration.OIDCResourceRetriever;

public class FileResourceRetriever extends OIDCResourceRetriever {

    private final String metadataFile;
    private final String jwksFile;

    public FileResourceRetriever(String metadataFile, String jwksFile) {
        this.metadataFile = metadataFile;
        this.jwksFile = jwksFile;
    } 
    
    @Override
	public Resource retrieveResource(URL url) throws IOException {
		String content = getContentFromFile(url); 	
    	return new Resource(content, "application/json");
	}

    private String getContentFromFile(URL url){
    	try {
	    	if (url.toString().contains("metadata")) {
	            return IOUtils.readInputStreamToString( getInputStream(metadataFile), Charset.forName("UTF-8"));
	        }
	        if (url.toString().contains("jwks")) {
	            return IOUtils.readInputStreamToString(getInputStream(jwksFile), Charset.forName("UTF-8"));
	        }
	        return null;
    	 } catch (IOException e) {
             throw new RuntimeException(e);
         }
    }
  
    private InputStream getInputStream(String file) throws IOException {
    	return FileResourceRetriever.class.getResourceAsStream(file);
    }
    
    @Override
    public String toString() {
        return getClass().getSimpleName() + " [metadataFile=" + metadataFile + ", jwksFile=" + jwksFile + "]";
    }
}
