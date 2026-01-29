# Databricks notebook source
# MAGIC %md
# MAGIC # Response Playbook #2023.4
# MAGIC # Active Directory User Disabling Playbook
# MAGIC
# MAGIC ## Overview
# MAGIC
# MAGIC This playbook is designed to automate the process of disabling a user in Active Directory. It can be triggered either manually or automatically based on user behavior. It is primarily intended for use by security analysts.
# MAGIC
# MAGIC ## Trigger
# MAGIC
# MAGIC The playbook is triggered in two ways:
# MAGIC
# MAGIC 1. **Automatically**: Based on user behavior that meets certain predefined conditions.
# MAGIC 2. **Manually**: A security analyst can initiate the playbook as needed.
# MAGIC
# MAGIC ## Process
# MAGIC
# MAGIC The playbook follows these steps:
# MAGIC
# MAGIC 1. It pulls the user details from one of three potential sources:
# MAGIC    - The response table
# MAGIC    - Data passed across tasks in a Databricks job
# MAGIC    - A notebook widget
# MAGIC
# MAGIC 2. It connects to the Azure AD Graph API.
# MAGIC
# MAGIC 3. It disables the specified users in Active Directory.
# MAGIC
# MAGIC ## Outcome
# MAGIC
# MAGIC Upon successful execution, the specified user accounts will be disabled in Active Directory.
# MAGIC
# MAGIC ## Logging and Reporting
# MAGIC
# MAGIC The execution of this playbook is carried out in a Databricks job, which records the outcome of the notebook's run. This allows for easy tracking and auditing of the actions taken by the playbook.
# MAGIC
# MAGIC ## Risks and Cautions
# MAGIC
# MAGIC While this playbook automates a critical security function, it's essential to be aware of potential risks. Automated disabling of users can potentially impact users who shouldn't be disabled. Therefore, ensuring the accuracy of the conditions that trigger the playbook is crucial.
# MAGIC
# MAGIC ## Re-enabling Users
# MAGIC
# MAGIC If a user has been disabled in error, they can be re-enabled manually in Azure AD.
# MAGIC

# COMMAND ----------

# DBTITLE 1,Load Widget
# dbutils.widgets.text("User", defaultValue="", label="User ID")

# COMMAND ----------

# DBTITLE 1,Load Azure AD Libraries
# MAGIC %pip install adal msrest msal

# COMMAND ----------

dbutils.library.restartPython()

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC ## Step 1: Pull User Details
# MAGIC
# MAGIC The first step in this playbook is to gather the necessary user details. This information can come from one of three sources:
# MAGIC
# MAGIC 1. **Response Table**: The response table is a structured data source that contains information about users and their activities. This could include the user's ID, username, or other identifying information.
# MAGIC
# MAGIC 2. **Databricks Job Data**: If this playbook is being triggered as part of a Databricks job, it can use data passed between tasks within that job. This might include user details that have been gathered or processed by earlier tasks in the job.
# MAGIC
# MAGIC 3. **Notebook Widget**: If the playbook is being run from a Databricks notebook, it can pull user details from a notebook widget. This could be a form or other interactive element allowing users to input or select information.
# MAGIC
# MAGIC The playbook will use these details to identify the specific user or users who need to be disabled in Active Directory.

# COMMAND ----------

# DBTITLE 1,Load User from Job or Widget
# MAGIC %skip
# MAGIC # Get the user ID from either the task, or from the widget
# MAGIC username = None
# MAGIC
# MAGIC # If the widget doesn't have a user defined
# MAGIC if username is None or user == "":
# MAGIC     try:
# MAGIC         username = dbutils.jobs.taskValues.get(taskKey = "Investigate_Suspicious_User", key = "user", debugValue = "DEBUG_UNDEFINED")
# MAGIC     except ValueError:
# MAGIC         print("Error: no task value to pull from job")
# MAGIC         username=None
# MAGIC
# MAGIC # If the user is not defined, try the widget 
# MAGIC if username is None or username=="DEBUG_UNDEFINED" or username == "":
# MAGIC     username = dbutils.widgets.get("User")
# MAGIC
# MAGIC
# MAGIC if username is None or username=="DEBUG_UNDEFINED" or username == "":
# MAGIC     print("ERROR: No username to disable. Exit gacefully")
# MAGIC     exit(0)
# MAGIC
# MAGIC print("---------------------------------------")
# MAGIC print(f"The user being disabled is '{username}'")
# MAGIC print("---------------------------------------")

# COMMAND ----------

# DBTITLE 1,Load User from Job or Widget with LLM
# Get the user ID from either the task, or from the widget
username = None

# If the widget doesn't have a user defined
if username is None or username == "":
    try:
        username = dbutils.jobs.taskValues.get(taskKey = "Investigate_Suspicious_User_With_LLM", key = "user", debugValue = "DEBUG_UNDEFINED")
        print(f"Get user '{username}' from taskKey='Investigate_Suspicious_User_With_LLM'")
    except ValueError:
        print("Error: no task value to pull from job")
        username=None

# If the user is not defined, try the widget 
if username is None or username=="DEBUG_UNDEFINED" or username == "":
    username = dbutils.widgets.get("User")


if username is None or username=="DEBUG_UNDEFINED" or username == "":
    print("ERROR: No username to disable. Exit gacefully")
    exit(0)

print("---------------------------------------")
print(f"The user being disabled is '{username}'")
print("---------------------------------------")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2: Connect to Azure AD Graph API and Disable User
# MAGIC
# MAGIC Once the playbook has the necessary user details, it will connect to the Azure AD Graph API. This web-based service provided by Microsoft allows for programmatic access to Azure Active Directory.
# MAGIC
# MAGIC The playbook will authenticate with the API using the necessary credentials (these should be securely stored and managed to ensure they are not exposed or compromised).
# MAGIC
# MAGIC Once connected to the API, the playbook will request to disable the specified user or users. This is done by setting the 'accountEnabled' attribute of the user object to 'false'.
# MAGIC
# MAGIC The API will respond with a status code and message indicating whether the request was successful. If the request fails, the playbook should have error handling to log the failure and alert the appropriate personnel.

# COMMAND ----------

# DBTITLE 1,Set Notebook Variables
# MAGIC %skip
# MAGIC import requests
# MAGIC from msal import ConfidentialClientApplication
# MAGIC
# MAGIC
# MAGIC ###########################
# MAGIC ## CHANGE ME AS REQUIRED ##
# MAGIC ###########################
# MAGIC
# MAGIC # Set this variable to True if the Graph API token and user account is configured.
# MAGIC ENABLE_DEMO = False
# MAGIC
# MAGIC # Create a Databricks secret and set three keys that are specific to your Azure environment
# MAGIC # To set up an Azure developer environment, follow https://azure.microsoft.com/en-ca/products/deployment-environments and create a Databricks secret 
# MAGIC SECRET_SCOPE = "suspicious_user_demo_scope"
# MAGIC AZURE_CLIENT_ID_KEY = "Azure_Client_ID"
# MAGIC AZURE_APP_SECRET_KEY = "Azure_App_Secret"
# MAGIC AZURE_TENANT_ID = "Azure_Tenant_ID"

# COMMAND ----------

# DBTITLE 1,Disable User in Azure AD
# MAGIC %skip
# MAGIC def disable_user(user_id):
# MAGIC     """
# MAGIC     Disables a user in Azure Active Directory using the Microsoft Graph API.
# MAGIC     
# MAGIC     Parameters:
# MAGIC         - user_id (str): The ID of the user to disable.
# MAGIC     
# MAGIC     Returns:
# MAGIC         None
# MAGIC     """
# MAGIC     # Get API Token details from Databricks Secrets Manager
# MAGIC     client_id = dbutils.secrets.get(scope = SECRET_SCOPE, key = AZURE_CLIENT_ID_KEY)
# MAGIC     client_secret = dbutils.secrets.get(scope = SECRET_SCOPE, key = AZURE_APP_SECRET_KEY)
# MAGIC     tenant_id = dbutils.secrets.get(scope = SECRET_SCOPE, key = AZURE_TENANT_ID)
# MAGIC     
# MAGIC     # Get the Azure API App context
# MAGIC     app = ConfidentialClientApplication(
# MAGIC         client_id,
# MAGIC         authority=f"https://login.microsoftonline.com/{tenant_id}",
# MAGIC         client_credential=client_secret,
# MAGIC     )
# MAGIC     
# MAGIC     # Request a token
# MAGIC     result = app.acquire_token_for_client(["https://graph.microsoft.com/.default"])
# MAGIC     
# MAGIC     # Use the token to make an API request to disable the user
# MAGIC     if "access_token" in result:
# MAGIC         token = result["access_token"]
# MAGIC         headers = {
# MAGIC             'Authorization': f'Bearer {token}',
# MAGIC             'Content-type' : 'application/json'
# MAGIC         }
# MAGIC         data = {
# MAGIC             "accountEnabled": False
# MAGIC         }
# MAGIC         response = requests.patch(f'https://graph.microsoft.com/v1.0/users/{user_id}', headers=headers, json=data)
# MAGIC         if response.status_code == 204:
# MAGIC             print(f"Successfully disabled user '{username}' (UID: '{user_id}').")
# MAGIC         else:
# MAGIC             raise ValueError(f'Could not disable user {user_id}. The API response was: {response.content}')
# MAGIC     else:
# MAGIC         # Print any error messages from requesting the API token
# MAGIC         print(result.get("error"))
# MAGIC         print(result.get("error_description"))
# MAGIC         print(result.get("correlation_id"))  # You may need this when reporting a bug
# MAGIC
# MAGIC
# MAGIC def disable_user_by_username(username):
# MAGIC     """
# MAGIC     Disables a user in Azure Active Directory using the Microsoft Graph API, given a username.
# MAGIC     
# MAGIC     Parameters:
# MAGIC         - username (str): The username of the user to disable.
# MAGIC     
# MAGIC     Returns:
# MAGIC         None
# MAGIC     """
# MAGIC     # Get the user GUID from the users table
# MAGIC     df = spark.sql(f"SELECT ID FROM delta.`/tmp/detection_maturity/tables/users` WHERE Username = '{username}'")
# MAGIC     
# MAGIC     # Disable the user by the GUID
# MAGIC     if df.count() > 0:
# MAGIC         disable_user(df.first()['ID'])
# MAGIC     else:
# MAGIC          raise ValueError(f"Invalid user '{user}' passed to Notebook.") 
# MAGIC
# MAGIC
# MAGIC # Call the disable_user_by_username function with a specific user 
# MAGIC if ENABLE_DEMO:
# MAGIC     disable_user_by_username(username)
