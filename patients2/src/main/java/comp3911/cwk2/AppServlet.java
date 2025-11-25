package comp3911.cwk2;

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.sql.PreparedStatement;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mindrot.jbcrypt.BCrypt;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;
import freemarker.core.HTMLOutputFormat; // We need to import the HTML format so that we can use it when specifying 

@SuppressWarnings("serial")
public class AppServlet extends HttpServlet {

  private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";
  private static final String AUTH_QUERY = "select password from user where username='%s'";
  private static final String SEARCH_QUERY = "select * from patient where surname='%s' collate nocase";

  private final Configuration fm = new Configuration(Configuration.VERSION_2_3_28);
  private Connection database;

  @Override
  public void init() throws ServletException {
    configureTemplateEngine();
    connectToDatabase();
  }

  private void configureTemplateEngine() throws ServletException {
    try {
      fm.setDirectoryForTemplateLoading(new File("./templates"));
      fm.setDefaultEncoding("UTF-8");
      fm.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);
      fm.setLogTemplateExceptions(false);
      fm.setWrapUncheckedExceptions(true);

      // XSS sanitization
      fm.setOutputFormat(HTMLOutputFormat.INSTANCE); // Specify the output format so that FreeMaker can automatically escape HTML and JS tags
      fm.setRecognizeStandardFileExtensions(true); // Allow FreeMaker to automatically recognize HTML type files as HTML and apply the XSS sanitization
    }
    catch (IOException error) {
      throw new ServletException(error.getMessage());
    }
  }

  private void connectToDatabase() throws ServletException {
    try {
      database = DriverManager.getConnection(CONNECTION_URL);
    }
    catch (SQLException error) {
      throw new ServletException(error.getMessage());
    }
  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
          throws ServletException, IOException {
    try {
      Template template = fm.getTemplate("login.html");
      template.process(null, response.getWriter());
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    }
    catch (TemplateException error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
          throws ServletException, IOException {
    // Get form parameters
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    String surname = request.getParameter("surname");

    try {
      if (authenticated(username, password)) {
        // Get search results and merge with template
        Map<String, Object> model = new HashMap<>();
        model.put("records", searchResults(surname));
        Template template = fm.getTemplate("details.html");
        template.process(model, response.getWriter());
      }
      else {
        Template template = fm.getTemplate("invalid.html");
        template.process(null, response.getWriter());
      }
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    }
    catch (Exception error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

/*
     This fix involves further modifying the code for deciding whether
     a user is authenticated or not. In addition to hashing the passwords.
     A prepared statement is used to ensure that SQL injection attacks are not possible.
     The query retrieves the stored hashed password, and BCrypt is used to compare it
     with the plaintext user input.
  */
  private boolean authenticated(String username, String password) throws SQLException {
    // query db using username to find stored password - fixing flaw 3
    String query = String.format(AUTH_QUERY, username);


    try (PreparedStatement stmt = database.prepareStatement(query)) {
      // bind the username to the prepared statement
      stmt.setString(1, username);

      ResultSet results = stmt.executeQuery(query);
      if (!results.next()) {
        // username not found
        return false;
      }
      // get the stored hashed password from the DB
      String storedHash = results.getString("password");
      // compare plaintext input password with the stored hash
      return BCrypt.checkpw(password, storedHash);
    }
  }

  
   private List<Record> searchResults(String surname) throws SQLException {
    List<Record> records = new ArrayList<>();

    // sanitize string by escaping quotes
    String sanitizedSurname = surname.replace("'", "''");

    // use sanitized string
    String query = String.format(SEARCH_QUERY, sanitizedSurname);

    try (Statement stmt = database.createStatement()) {
      ResultSet results = stmt.executeQuery(query);
      while (results.next()) {
        Record rec = new Record();
        rec.setSurname(results.getString(2));
        rec.setForename(results.getString(3));
        rec.setAddress(results.getString(4));
        rec.setDateOfBirth(results.getString(5));
        rec.setDoctorId(results.getString(6));
        rec.setDiagnosis(results.getString(7));
        records.add(rec);
      }
    }
    return records;
  }
}
