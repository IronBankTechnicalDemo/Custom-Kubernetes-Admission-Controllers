### Validation and Mutating Webhooks

This project provides a single image and Helm chart that does the following:
1. Image contains both an admission and mutating webhook to ensure:
  * No privileged escalation in pods or deployments
  * The container runs as a random UID that is in the 'root' (0) group.
  * Filesystems mounted to the pods will be mounted as the 'root' (0) group to give the user access.
2. The helm chart deploys both the validation and mutating webhooks into your environment.
    * It also manages the creation of certificates required for TLS communication to the validation/mutating container using the Sprig-supplied TLS functionality.
    
    
*How to Deploy*

Deployment of the webhook is simple. Ensure you have Helm installed, and run the following:

```
helm install secure-webhooks chart/
```

