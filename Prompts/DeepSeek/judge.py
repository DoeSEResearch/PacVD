import json
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score, matthews_corrcoef, confusion_matrix
from collections import Counter


def evaluate_predictions(filename):
    targets = []
    preds = []
    normal_count = 0
    abnormal_count = 0

    try:
        # Read the file and parse data
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                obj = json.loads(line.strip())  # Ensure each line is valid JSON
                target = 0 if obj['original_cls'] == 0 else 1
                prediction = obj.get('prediction_label', -1)  # Support new key names

                # Skip abnormal predictions
                if prediction == -1:
                    abnormal_count += 1
                    continue

                normal_count += 1
                targets.append(target)
                preds.append(prediction)

        # Check if there are valid predictions
        if not preds:
            print("No valid predictions found.")
            return

        # Print the distribution of targets and predictions to check for imbalance issues
        print("Target distribution:", Counter(targets))
        print("Prediction distribution:", Counter(preds))

        # Calculate evaluation metrics, rounded to 4 decimal places
        acc = round(accuracy_score(targets, preds), 4)
        recall = round(recall_score(targets, preds, average='binary'), 4)
        precision = round(precision_score(targets, preds, average='binary'), 4)
        f1 = round(f1_score(targets, preds, average='binary'), 4)
        mcc = round(matthews_corrcoef(targets, preds), 4)

        # Output the confusion matrix
        cm = confusion_matrix(targets, preds)
        print("\nConfusion Matrix:")
        print(cm)

        # Summarize results and print them
        result = {
            "eval_accuracy": acc,
            "eval_precision": precision,
            "eval_recall": recall,
            "eval_f1": f1,
            "eval_mcc": mcc,
            "normal_count": normal_count,
            "abnormal_count": abnormal_count,
            "confusion_matrix": cm.tolist()  # Convert to list format for JSON serialization
        }

        print("\nEvaluation Results:")
        for key, value in result.items():
            print(f"{key}: {value}")

        # Save evaluation results to a file
        output_file = filename.replace(".json", "_eval_results.json")
        with open(output_file, 'w', encoding='utf-8') as out_f:
            json.dump(result, out_f, indent=4)
        print(f"\nEvaluation results saved to {output_file}")

    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
    except json.JSONDecodeError:
        print(f"Error: Failed to decode JSON from file {filename}.")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")


if __name__ == '__main__':
    filename = '../../result/...'  # Change to the actual file path
    evaluate_predictions(filename)