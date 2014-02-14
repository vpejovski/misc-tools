package com.sce.cloudservices.ldap.userchk;

import java.util.Hashtable;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.ServletContext;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;

@Path("/checkuid")
@Produces("text/html")
public class CheckUID {

	@Context
	private ServletContext sc;

	@GET
	@Path("/{userid}")
	public String CheckUserIdLdap(@PathParam("userid") String userID) {
		this.sc.log("Userid received : " + userID);

		if (checkUIDInLDAP(userID)) {
			return String.format("%s %s %s", "{ \"ValidUserId\":",
					Boolean.toString(true), "}");
		} else {
			return String.format("%s %s %s", "{ \"ValidUserId\":",
					Boolean.toString(false), "}");
		}
	}

	private boolean checkUIDInLDAP(String userID) {
		/*
		 * sAMAccountName = windows user id
		 */

		boolean result = false;
		DirContext ctx = null;

		Hashtable<String, String> env = new Hashtable<String, String>();
		env.put(javax.naming.Context.INITIAL_CONTEXT_FACTORY,
				"com.sun.jndi.ldap.LdapCtxFactory");
		env.put(javax.naming.Context.SECURITY_AUTHENTICATION, "simple");

		env.put(javax.naming.Context.PROVIDER_URL,
				this.sc.getInitParameter("ldapUrl"));
		env.put(javax.naming.Context.SECURITY_PRINCIPAL,
				this.sc.getInitParameter("username"));
		env.put(javax.naming.Context.SECURITY_CREDENTIALS,
				this.sc.getInitParameter("password"));

		String searchBase = this.sc.getInitParameter("searchBase");

		try {
			ctx = new InitialDirContext(env);

			SearchControls searchCtls = new SearchControls();

			String returnedAtts[] = { "sn", "givenName", "samAccountName" };
			searchCtls.setReturningAttributes(returnedAtts);

			searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

			String searchFilter = String.format("(&(samAccountName=%s))",
					userID);

			int totalResults = 0;

			NamingEnumeration<SearchResult> answer = ctx.search(searchBase,
					searchFilter, searchCtls);

			while (answer.hasMoreElements()) {
				SearchResult sr = (SearchResult) answer.next();
				Attributes attrs = sr.getAttributes();

				if (attrs.get("samAccountName").get(0).toString()
						.equalsIgnoreCase(userID)) {
					totalResults++;
				}
			}

			if (totalResults > 0) {
				result = true;
			}

		} catch (NamingException e) {
			this.sc.log(e.getMessage(), e);

		} finally {

			if (ctx != null) {
				try {
					ctx.close();

				} catch (NamingException e) {
					this.sc.log(e.getMessage(), e);
				}
			}
		}

		return result;
	}

}
