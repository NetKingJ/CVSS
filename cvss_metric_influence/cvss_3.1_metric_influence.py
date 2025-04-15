from itertools import product
from cvss import CVSS3

# CVSS 3.1 메트릭 정의
metrics = {
    'AV': ['N', 'A', 'L', 'P'],
    'AC': ['L', 'H'],
    'PR': ['N', 'L', 'H'],
    'UI': ['N', 'R'],
    'S': ['U', 'C'],
    'C': ['H', 'L', 'N'],
    'I': ['H', 'L', 'N'],
    'A': ['H', 'L', 'N']
}

def metric_influence(metric_name):
    # 이 메트릭을 제외한 나머지 메트릭들의 조합
    other_metrics = {m: v for m, v in metrics.items() if m != metric_name}
    all_combinations = product(*other_metrics.values())
    differences = []
    
    for comb in all_combinations:
        # 현재 조합을 딕셔너리 형태로 매핑
        fixed = dict(zip(other_metrics.keys(), comb))
        
        scores = []
        for val in metrics[metric_name]:
            # 벡터 문자열 생성
            vector_parts = []
            # S를 항상 AV,AC,PR,UI 다음에 위치시키기 위해 순서를 맞춰준다.
            # (CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X)
            vector_order = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
            
            # fixed 딕셔너리를 vector_order 순서에 맞게 다시 구성
            vector_values = {}
            for m in vector_order:
                if m == metric_name:
                    vector_values[m] = val
                else:
                    vector_values[m] = fixed[m]
            
            vector_str = "CVSS:3.1/" + "/".join([f"{m}:{v}" for m,v in vector_values.items()])
            cvss = CVSS3(vector_str)
            score = cvss.scores()[0]
            scores.append(score)
        
        # 해당 조합에서 해당 메트릭을 바꿨을 때 발생하는 점수 차이
        diff = max(scores) - min(scores)
        differences.append(diff)
    
    # 평균 영향도
    return sum(differences) / len(differences) if differences else 0

# 모든 메트릭에 대해 영향도 계산
influences = {}
for m in metrics:
    influences[m] = metric_influence(m)

# 영향도가 높은 순으로 정렬
sorted_by_influence = sorted(influences.items(), key=lambda x: x[1], reverse=True)

# 결과 출력
print("CVSS 3.1 메트릭 영향도 순서(내림차순):")
for metric, inf in sorted_by_influence:
    print(f"{metric}: {inf}")
