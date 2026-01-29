# Databricks notebook source
# MAGIC %md This notebook sets up the companion cluster(s) to run the solution accelerator. It also creates the Workflow to illustrate the order of execution. Happy exploring! 
# MAGIC 🎉
# MAGIC
# MAGIC **Steps**
# MAGIC 1. Simply attach this notebook to a cluster and hit Run-All for this notebook. A multi-step job and the clusters used in the job will be created for you and hyperlinks are printed on the last block of the notebook. 
# MAGIC
# MAGIC 2. Run the accelerator notebooks: Feel free to explore the multi-step job page and **run the Workflow**, or **run the notebooks interactively** with the cluster to see how this solution accelerator executes. 
# MAGIC
# MAGIC     2a. **Run the Workflow**: Navigate to the Workflow link and hit the `Run Now` 💥. 
# MAGIC   
# MAGIC     2b. **Run the notebooks interactively**: Attach the notebook with the cluster(s) created and execute as described in the `job_json['tasks']` below.
# MAGIC
# MAGIC **Prerequisites** 
# MAGIC 1. You need to have cluster creation permissions in this workspace.
# MAGIC
# MAGIC 2. In case the environment has cluster-policies that interfere with automated deployment, you may need to manually create the cluster in accordance with the workspace cluster policy. The `job_json` definition below still provides valuable information about the configuration these series of notebooks should run with. 
# MAGIC
# MAGIC **Notes**
# MAGIC 1. The pipelines, workflows and clusters created in this script are not user-specific. Keep in mind that rerunning this script again after modification resets them for other users too.
# MAGIC
# MAGIC 2. If the job execution fails, please confirm that you have set up other environment dependencies as specified in the accelerator notebooks. Accelerators may require the user to set up additional cloud infra or secrets to manage credentials. 

# COMMAND ----------

# MAGIC %pip install -U git+https://github.com/databricks-academy/dbacademy@v1.0.14 git+https://github.com/databricks-industry-solutions/notebook-solution-companion@safe-print-html --quiet --disable-pip-version-check

# COMMAND ----------

dbutils.library.restartPython()

# COMMAND ----------

# MAGIC %skip
# MAGIC from solacc.companion import NotebookSolutionCompanion

# COMMAND ----------

# MAGIC %skip
# MAGIC job_json = {
# MAGIC     "name": "Threat_Detection_Investigation",
# MAGIC     "email_notifications": {
# MAGIC         "no_alert_for_skipped_runs": False
# MAGIC     },
# MAGIC     "webhook_notifications": {},
# MAGIC     "timeout_seconds": 0,
# MAGIC     "max_concurrent_runs": 1,
# MAGIC     "tasks": [
# MAGIC         {
# MAGIC             "task_key": "Generate_Data",
# MAGIC             "run_if": "ALL_SUCCESS",
# MAGIC             "notebook_task": {
# MAGIC                 "notebook_path": f"/0.1 Data Creation",
# MAGIC                 "source": "WORKSPACE"
# MAGIC             },
# MAGIC             "job_cluster_key": "Threat_Detection_Cluster",
# MAGIC             "timeout_seconds": 0,
# MAGIC             "email_notifications": {}
# MAGIC         },
# MAGIC         {
# MAGIC             "task_key": "Investigate_Suspicious_Sharepoint_Activity",
# MAGIC             "depends_on": [
# MAGIC                 {
# MAGIC                     "task_key": "Generate_Data"
# MAGIC                 }
# MAGIC             ],
# MAGIC             "run_if": "ALL_SUCCESS",
# MAGIC             "notebook_task": {
# MAGIC                 "notebook_path": f"/1.1 [Detection] Investigate Suspicious Document Access Activity",
# MAGIC                 "source": "WORKSPACE"
# MAGIC             },
# MAGIC             "job_cluster_key": "Threat_Detection_Cluster",
# MAGIC             "timeout_seconds": 0,
# MAGIC             "email_notifications": {}
# MAGIC         },
# MAGIC         {
# MAGIC             "task_key": "Suspicious_Number_Of_Emails_Sent_By_Employee",
# MAGIC             "depends_on": [
# MAGIC                 {
# MAGIC                     "task_key": "Generate_Data"
# MAGIC                 }
# MAGIC             ],
# MAGIC             "run_if": "ALL_SUCCESS",
# MAGIC             "notebook_task": {
# MAGIC                 "notebook_path": f"1.2 [Detection] Suspicious Number of Emails Sent by Sender",
# MAGIC                 "source": "WORKSPACE"
# MAGIC             },
# MAGIC             "job_cluster_key": "Threat_Detection_Cluster",
# MAGIC             "timeout_seconds": 0,
# MAGIC             "email_notifications": {}
# MAGIC         },
# MAGIC         {
# MAGIC             "task_key": "Investigate_Suspicious_User",
# MAGIC             "depends_on": [
# MAGIC                 {
# MAGIC                     "task_key": "Investigate_Suspicious_Sharepoint_Activity"
# MAGIC                 },
# MAGIC                 {
# MAGIC                     "task_key": "Suspicious_Number_Of_Emails_Sent_By_Employee"
# MAGIC                 }
# MAGIC             ],
# MAGIC             "run_if": "ALL_SUCCESS",
# MAGIC             "notebook_task": {
# MAGIC                 "notebook_path": f"2.1 [Investigation] Investigate Suspicious User",
# MAGIC                 "source": "WORKSPACE"
# MAGIC             },
# MAGIC             "job_cluster_key": "Threat_Detection_Cluster",
# MAGIC             "timeout_seconds": 0,
# MAGIC             "email_notifications": {}
# MAGIC         },
# MAGIC         {
# MAGIC             "task_key": "Disable_Suspicious_User",
# MAGIC             "depends_on": [
# MAGIC                 {
# MAGIC                     "task_key": "Investigate_Suspicious_User"
# MAGIC                 }
# MAGIC             ],
# MAGIC             "run_if": "ALL_SUCCESS",
# MAGIC             "notebook_task": {
# MAGIC                 "notebook_path": f"3.1 [Response] Disable Suspicious User",
# MAGIC                 "source": "WORKSPACE"
# MAGIC             },
# MAGIC             "job_cluster_key": "Threat_Detection_Cluster",
# MAGIC             "timeout_seconds": 0,
# MAGIC             "email_notifications": {}
# MAGIC         }
# MAGIC     ],
# MAGIC     "job_clusters": [
# MAGIC       {
# MAGIC         "job_cluster_key": "Threat_Detection_Cluster",
# MAGIC         "new_cluster": {
# MAGIC           "cluster_name": "",
# MAGIC           "spark_version": "15.4.x-scala2.12",
# MAGIC           "spark_conf": {
# MAGIC             "spark.master": "local[*, 4]",
# MAGIC             "spark.databricks.cluster.profile": "singleNode"
# MAGIC           },
# MAGIC           "aws_attributes": {
# MAGIC             "first_on_demand": 1,
# MAGIC             "availability": "SPOT_WITH_FALLBACK",
# MAGIC             "zone_id": "us-west-2a",
# MAGIC             "spot_bid_price_percent": 100
# MAGIC           },
# MAGIC           "node_type_id": {"AWS": "m5d.large", "MSA": "Standard_DS3_v2", "GCP": "n1-highmem-4"},
# MAGIC           "driver_node_type_id": "m5d.large",
# MAGIC           "custom_tags": {
# MAGIC             "ResourceClass": "SingleNode"
# MAGIC           },
# MAGIC           "enable_elastic_disk": true,
# MAGIC           "data_security_mode": "SINGLE_USER",
# MAGIC           "runtime_engine": "PHOTON",
# MAGIC           "num_workers": 0
# MAGIC         }
# MAGIC       }
# MAGIC     ],
# MAGIC     "tags": {
# MAGIC         "ID": "2024.01.10",
# MAGIC         "Team": "Cybersecurity"
# MAGIC     },
# MAGIC     "format": "MULTI_TASK"
# MAGIC }

# COMMAND ----------

# MAGIC %skip
# MAGIC dbutils.widgets.dropdown("run_job", "False", ["True", "False"])
# MAGIC run_job = dbutils.widgets.get("run_job") == "True"
# MAGIC NotebookSolutionCompanion().deploy_compute(job_json, run_job=run_job)

# COMMAND ----------

# DBTITLE 1,Create a job to run on Serverless cluster for Databricks Free Edition
import time 
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.jobs import Task, NotebookTask, TaskDependency, JobEmailNotifications, TaskEmailNotifications

w = WorkspaceClient()

email = "____@gmail.com" # insert your own email
job_name = "Threat Detection with LLM"
existing_jobs = [j for j in w.jobs.list() if j.settings and j.settings.name == job_name]

if existing_jobs:
    print(f"Job name='{job_name}' already exist (job_id={existing_jobs[0].job_id}). Please delete it in the GUI before creating it.")
else:
    job = w.jobs.create(
        name = job_name,
        timeout_seconds = 0,
        max_concurrent_runs=1,
        email_notifications = JobEmailNotifications(
            on_success = [email],
            on_failure = [email]
        ),
        tasks = [
            Task(
                task_key = "Generate_Data",
                timeout_seconds = 0,
                description = "Generate Sample Data",
                notebook_task = NotebookTask(
                    notebook_path = "/Workspace/Users/Threat-Detection-With-LLM/0.1 Data Creation", # paste your own notebook file path
                    base_parameters = {"cluster-name": "Serverless"},
                ),
                email_notifications = TaskEmailNotifications(
                    on_success = [email],
                    on_failure = [email]
                )
            ),
            Task(
                task_key = "Investigate_Suspicious_Sharepoint_Activity",
                timeout_seconds = 0,
                description = "Investigate Suspivious Sharepoint Activity",
                depends_on = [TaskDependency(task_key = "Generate_Data")],
                notebook_task = NotebookTask(
                    notebook_path = "/Workspace/Users/Threat-Detection-With-LLM/1.1 [Detection] Investigate Suspicious Document Access Activity", # paste your own notebook file path
                    base_parameters = {"cluster-name": "Serverless"},
                ),
                email_notifications = TaskEmailNotifications(
                    on_success = [email],
                    on_failure = [email]
                )
            ),
            Task(
                task_key = "Suspicious_Number_Of_Emails_Sent_By_Employee",
                timeout_seconds = 0,
                description = "Suspicious Number Of Emails Sent By Employee",
                depends_on = [TaskDependency(task_key = "Generate_Data")],
                notebook_task = NotebookTask(
                    notebook_path = "/Workspace/Users/Threat-Detection-With-LLM/1.2 [Detection] Suspicious Number of Emails Sent by Sender", # paste your own notebook file path
                    base_parameters = {"cluster-name": "Serverless"},
                ),
                email_notifications = TaskEmailNotifications(
                    on_success = [email],
                    on_failure = [email]
                )
            ),
            Task(
                task_key = "Investigate_Suspicious_User_With_LLM",
                timeout_seconds = 0,
                description = "Investigate Suspicious User With LLM",
                depends_on = [TaskDependency(task_key = "Investigate_Suspicious_Sharepoint_Activity"),
                              TaskDependency(task_key = "Suspicious_Number_Of_Emails_Sent_By_Employee")],
                notebook_task = NotebookTask(
                    notebook_path = "/Workspace/Users//Threat-Detection-With-LLM/2.2 [Investigation] Investigate Suspicious User with LLM", # paste your own notebook file path
                    base_parameters = {"cluster-name": "Serverless"},
                ),
                email_notifications = TaskEmailNotifications(
                    on_success = [email],
                    on_failure = [email]
                )
            ),
            Task(
                task_key = "Disable_Suspicious_User",
                timeout_seconds = 0,
                description = "Disable Suspicious User",
                depends_on = [TaskDependency(task_key = "Investigate_Suspicious_User_With_LLM")],
                notebook_task = NotebookTask(
                    notebook_path = "/Workspace/Users/Threat-Detection-With-LLM/3.1 [Response] Disable Suspicious User", # paste your own notebook file path
                    base_parameters = {"cluster-name": "Serverless"},
                ),
                email_notifications = TaskEmailNotifications(
                    on_success = [email],
                    on_failure = [email]
                )
            )
        ]
    )
    job_id = job.job_id
    print(f"Job name='{job_name}' (job_id={job_id}) has been created successully and will start run after 30 seconds.")
    time.sleep(30)
    run = w.jobs.run_now(job_id)
    run_id = run.run_id
    print(f"Job name='{job_name}' (job_id={job_id}) with run_id={run_id} has been started and is running.")

