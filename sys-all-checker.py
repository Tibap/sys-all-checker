#!/usr/bin/env python3

import google.auth
from google.cloud import resource_manager
from google.cloud.container_v1 import ClusterManagerClient
from kubernetes import client as kubClient
import urllib3
import csv
import logging

if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)
    logger = logging.getLogger('sys-all-checker')

    logger.info("Authenticating to GCP")
    credentials, project_id = google.auth.default()

    dangerous_groups = ['system:authenticated', 'system:anonymous', 'system:unauthenticated']
    normal_cluster_roles = ['system:basic-user', 'system:discovery', 'system:public-info-viewer']

    NB_CLUSTERS = 0
    NB_PROJECTS = 0
    dangerous_bindings = [['Project Id', 'Cluster Name', '(Cluster) Role Binding', 'Cluster Role', 'Subject Name']]
    
    logger.debug("Instanciating resource_manager client")
    client = resource_manager.Client()
    logger.debug("Instanciating ClusterManagerClient")
    container_client = ClusterManagerClient(credentials=credentials)

    # Disable urllib3 warnings when looping through clusters
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    logger.info("Looping through projects you have access to")
    for project in client.list_projects():
        NB_PROJECTS+=1
        try:
            resp = container_client.list_clusters(project_id=project.project_id, zone='-')
        except:
            continue # Container API is not enabled on this project

        if resp:
            try:
                NB_CLUSTERS+=len(resp.clusters)
                for cluster in resp.clusters:
                    logger.info(f"Checking cluster: {cluster.name} in project id: {project.project_id}")

                    # If cluster is private, skip
                    if not cluster.master_authorized_networks_config.gcp_public_cidrs_access_enabled:
                        logger.debug("Cluster is not reachable from public CIDRs")
                        continue

                    # If cluster has an authorized network list enabled, skip
                    if cluster.master_authorized_networks_config.enabled:
                        if cluster.master_authorized_networks_config.cidr_blocks:
                            logger.debug(f"Cluster is only reachable from: {cluster.master_authorized_networks_config.cidr_blocks}")
                            continue

                    config = kubClient.Configuration()
                    # Make sure to query the public endpoint if it's configured
                    if cluster.private_cluster_config.public_endpoint:
                        config.host = f'https://{cluster.private_cluster_config.public_endpoint}:443'
                    else:
                        config.host = f'https://{cluster.endpoint}:443'

                    config.verify_ssl = False
                    config.api_key = {"authorization": "Bearer " + credentials.token}
                    kubClient.Configuration.set_default(config)

                    # Fetch existing bindings
                    rbac = kubClient.RbacAuthorizationV1Api()
                    try:
                        bindings = rbac.list_cluster_role_binding(timeout_seconds=3)
                    except kubClient.ApiException as e:
                        logger.warn(f"Exception when calling RbacAuthorizationV1Api->list_cluster_role_binding: {e}\n")
                        continue

                    # Check ClusterRole bindings
                    if bindings.items:
                        for binding in bindings.items:
                            if binding.subjects:
                                for subject in binding.subjects:
                                    if subject.name in dangerous_groups:
                                        if binding.metadata.name not in normal_cluster_roles:
                                            logger.info(f"!! ClusterRoleBinding '{binding.metadata.name}' binds ClusterRole '{binding.role_ref.name}' to '{subject.name}'")
                                            dangerous_bindings.append([
                                                project.project_id,
                                                cluster.name,
                                                binding.metadata.name,
                                                binding.role_ref.name,
                                                subject.name]
                                            )

                    # Check Role bindings
                    roleBindings = rbac.list_role_binding_for_all_namespaces()
                    if roleBindings.items:
                        for roleBinding in roleBindings.items:
                            if roleBinding.subjects:
                                for subject in roleBinding.subjects:
                                    if subject.name in dangerous_groups:
                                        logger.info(f"!! RoleBinding '{roleBinding.metadata.name}' binds Role '{roleBinding.role_ref.name}' to '{subject.name}'")
                                        dangerous_bindings.append([
                                            project.project_id,
                                            cluster.name,
                                            roleBinding.metadata.name,
                                            roleBinding.role_ref.name,
                                            subject.name]
                                        )

            except KeyError:
                pass

    logger.info(f"Scanned {NB_PROJECTS} projects with a total of {NB_CLUSTERS} clusters")
    logger.info(f"Found {len(dangerous_bindings)-1} dangerous bindings")
    if len(dangerous_bindings) > 1:
        filename='output.csv'
        logger.info(f"Check file '{filename}' for results exported as CSV")
        with open(filename, 'w', newline='') as f:
            wr = csv.writer(f, quoting=csv.QUOTE_NONE)
            wr.writerows(dangerous_bindings)
