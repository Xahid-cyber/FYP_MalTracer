# MalTracer - EMBER2024 ML Evaluation Evidence

Evaluation Date: 14 August 2026

## Methodology

MalTracer integrates official pre-trained EMBER2024 LightGBM classifiers.

The models were independently evaluated using labelled EMBER2024 test data.

Raw test records were deduplicated using SHA-256 before evaluation.
No conflicting labels were found among duplicate hashes.

Decision threshold for Accuracy, Precision, Recall and F1:
0.50

The Win64 model SHA-256 was verified against the official benchmark model:

8eddddc26eb346d74810a0dfcc672342eca5709ece4da259934d6d3c77ca971b

Feature vector size:
2568

LightGBM trees:
500


## Win64

Unique samples: 119,993
Benign: 59,993
Malicious: 60,000

Accuracy: 98.6699%
Precision: 98.8524%
Recall: 98.4833%
F1 Score: 98.6675%
ROC-AUC: 0.998851
PR-AUC: 0.998975
TPR @ approximately 1% FPR: 98.3033%

TN: 59,307
FP: 686
FN: 910
TP: 59,090


## PDF

Unique samples: 12,000
Benign: 6,000
Malicious: 6,000

Accuracy: 95.8583%
Precision: 99.1603%
Recall: 92.5000%
F1 Score: 95.7144%
ROC-AUC: 0.991255
PR-AUC: 0.993267
TPR @ approximately 1% FPR: 92.6833%

TN: 5,953
FP: 47
FN: 450
TP: 5,550


## APK

Unique samples: 48,000
Benign: 24,000
Malicious: 24,000

Accuracy: 94.1000%
Precision: 95.2385%
Recall: 92.8417%
F1 Score: 94.0248%
ROC-AUC: 0.986137
PR-AUC: 0.987086
TPR @ approximately 1% FPR: 81.4917%

TN: 22,886
FP: 1,114
FN: 1,718
TP: 22,282


## ELF

Unique samples: 5,989
Benign: 2,989
Malicious: 3,000

Accuracy: 96.5437%
Precision: 95.1796%
Recall: 98.0667%
F1 Score: 96.6015%
ROC-AUC: 0.992884
PR-AUC: 0.992967
TPR @ approximately 1% FPR: 90.0000%

TN: 2,840
FP: 149
FN: 58
TP: 2,942


## Important Interpretation

These values are format-specific benchmark results for the integrated
EMBER2024 machine-learning classifiers.

They are NOT a claim that MalTracer has 94-99% universal real-world
malware detection accuracy.

MalTracer uses ML as one static evidence signal together with other
contextual evidence such as YARA, VirusTotal, heuristics and static
analysis.

Raw EMBER model scores must not be interpreted as the final malware
probability.

## Presentation Statement

"We integrated official pre-trained EMBER2024 LightGBM classifiers into
MalTracer and independently evaluated them on labelled EMBER2024 test
data. The Win64 classifier achieved approximately 98.67% accuracy, while
PDF, APK and ELF classifiers achieved approximately 95.86%, 94.10% and
96.54% accuracy respectively. These results represent benchmark
performance of individual ML components rather than universal
real-world accuracy of MalTracer."
