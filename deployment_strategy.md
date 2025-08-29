# Deployment Strategy – Real-time PII Defense (Project Guardian 2.0)

## Architecture Choice
The most effective deployment location is at the **API Gateway layer** (e.g., Kong, Nginx, or Envoy) as a **plugin/sidecar** that inspects traffic before data enters internal services.

### Why API Gateway?
- **Central Control Point**: All incoming/outgoing data flows through it.
- **Low Latency**: Regex + lightweight masking adds minimal processing delay.
- **Scalability**: Can be deployed across multiple gateways in microservices.
- **Ease of Integration**: No need to rewrite each service; just add plugin.
- **Cost Effective**: Avoids duplicating PII protection logic across apps.

## Flow
1. **Ingress Traffic → Gateway Plugin**
   - Detects PII in request/response payloads.
   - Redacts/masks sensitive data before passing downstream.
2. **Application Layer**
   - Receives sanitized payload, reducing fraud/leak risks.
3. **Logging & Monitoring**
   - Redacted logs stored safely for audits.
   - Alerts triggered on repeated PII exposure attempts.

## Alternatives
- **DaemonSet on Kubernetes Nodes**: Good for cluster-wide enforcement.
- **Sidecar Container per Microservice**: More granular but higher overhead.
- **Browser Extension (Customer Side)**: Can block exposure but harder to enforce.

## Recommendation
**Primary deployment: API Gateway Plugin (Nginx/Envoy/Kong)**  
- High scalability, low latency, and cost-efficient.  
- Works seamlessly with both legacy APIs and microservices.  
- Easy rollout with CI/CD pipelines.  

## Future Enhancements
- Add **ML/NLP-based Named Entity Recognition** for unstructured text PII.  
- Integrate with **SIEM tools** for real-time fraud detection.  
- Implement **tokenization** instead of masking for reversible secure storage.
