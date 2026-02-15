import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModel
from tqdm import tqdm

class SideCalculator:
    def __init__(self, model_name="microsoft/codebert-base", device=None, batch_size=16):
        self.device = device if device else ("cuda" if torch.cuda.is_available() else "cpu")
        self.batch_size = batch_size
        print(f"Loading SIDE model ({model_name}) on {self.device}...")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModel.from_pretrained(model_name).to(self.device)
    
    def _get_embeddings(self, text_list):
        """
        Get embeddings for a list of texts in batches.
        Using the [CLS] token embedding.
        """
        all_embeddings = []
        
        # Filter out empty strings to prevent errors, replace with placeholder
        # But for index alignment we must keep them. CodeBERT handles empty string fine usually.
        
        for i in range(0, len(text_list), self.batch_size):
            batch_texts = text_list[i : i + self.batch_size]
            
            # Tokenize
            inputs = self.tokenizer(
                batch_texts, 
                return_tensors="pt", 
                padding=True, 
                truncation=True, 
                max_length=512
            ).to(self.device)
            
            with torch.no_grad():
                outputs = self.model(**inputs)
            
            # Use [CLS] token embedding (index 0)
            embeddings = outputs.last_hidden_state[:, 0, :]
            all_embeddings.append(embeddings.cpu())
            
        if not all_embeddings:
            return torch.tensor([])
            
        return torch.cat(all_embeddings, dim=0)

    def compute(self, summaries, codes):
        """
        Compute SIDE (Summary-Code Semantic Similarity).
        :param summaries: List of generated summaries [str]
        :param codes: List of corresponding source codes [str]
        :return: List of cosine similarity scores
        """
        if len(summaries) != len(codes):
            raise ValueError("Summaries and codes lists must have the same length.")

        print(f"Computing SIDE score for {len(summaries)} pairs...")
        
        # Calculate embeddings
        summary_embs = self._get_embeddings(summaries)
        code_embs = self._get_embeddings(codes)
        
        # Compute cosine similarity
        # summary_embs and code_embs are [N, D]
        cosine_scores = F.cosine_similarity(summary_embs, code_embs)
        
        return cosine_scores.tolist()
