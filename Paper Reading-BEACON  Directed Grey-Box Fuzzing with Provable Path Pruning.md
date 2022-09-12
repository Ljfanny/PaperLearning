# Paper Reading-BEACON : Directed Grey-Box Fuzzing with Provable Path Pruning

link: [Oakland22-Beacon.pdf (5hadowblad3.github.io)](https://5hadowblad3.github.io/files/Oakland22-Beacon.pdf)

## Abstract

Research Target: directed fuzzing

Recent Problem: 效率不够高，象征性地去执行冗余的程序路径，从而浪费算力

**Solution**: 

BEACON --->  effectively direct a grey-box fuzzer in the sea of paths in a provable manner  

轻量级静态代码分析 ---> prune 82.94%, 且能够保证剪枝的部分是无用路径

CVE: 的英文全称是“Common Vulnerabilities &amp; Exposures”通用漏洞披露。CVE就好像是一个字典表，为广泛认同的信息安全漏洞或					者已经暴露出来的弱点给出一个公共的名称。

## Ⅰ Introduction

The **key** to achieving practicality in directed fuzzing is to **reject the unreachable execution paths as early as possible**.

**infeasible-path-explosion problem**: 经常搜索大量不可达目标的路径

**previous fuzzers:** grey-box & white-box

both: 在24小时内不能重现漏洞；

directed white-box fuzzers: 利用符号执行去判断是否可达 ---> 解决路径约束; 规模限制;

directed grey-box fuzzers: 不会拒绝不可达路径，rely on prioritizing seeds according to their likelihood of reaching the target code using heuristics collected from the execution feedback(lightweight meta-heuristics, machine learning techniques)。

**BEACON: **

在可以忽略不计的时间里，直接剪枝不可达路径。

通过简单静态分析，估算程序中变量的近似值确认此路径不可达。

剪枝过程中可以做到：剪枝①在控制流图中不可达 ②可达目标路径但是路径不满足

对static analysis进行优化：①relationship preservation，可以保持一定的精度 ②bounded disjunction可以避免消耗大量算力在不必要的逻辑计算，以及规避详尽路径合并所带来的精度损失。

**Evaluation:**

依据重现CVE-identified漏洞的能力以及测试在新版本中是否修复来做评估。

**Implement:**

①设计快速精确的静态分析，计算达到给定测试目标的必要条件，从而过滤不可行状态；

②实现directed grey-box fuzzer，可以在可忽略的时间里剪枝大量不可达路径；

③提供试验数据证明高效性；

## Ⅱ Background

### Directed Grey-Box Fuzzing

#### Specifying the Targets

manually specify the target code & automatically specify the testing target

**Sanitizers**(请参考https://github.com/google/Sanitizers )已经成为静态和动态代码分析的非常有用的工具。通过使用适当的标志重新编译代码并链接到必要的库，可以检查内存错误(地址清理器)、未初始化的读取(内存清理器)、线程安全(线程清理器)和未定义的行为(未定义的行为清理器)相关的问题。与同类型分析工具相比，Sanitizers带来的性能损失通常要小得多，而且往往提供关于检测到的问题的更详细的信息。缺点是，代码(可能还有工具链的一部分)需要使用附加的标志重新编译。

1. **Semfuzz** leverages natural language processing to analyze bug reports and retrieves the potential buggy points as its targets. 
2. **ParmeSan** labels all the potential buggy points indicated by various sanitizers.

#### Reaching the Targets 

1. **AFLGo** defines the distance of a testing input towards a target basic block as the average of the distances between a block B and the target.

2. **Hawkeye** optimizes the distance metric with the intuition that a vulnerability is triggered by a sequence of operations rather than a single program point. 

3. **FuzzGuard** leverages an observation that reproducing a bug needs to satisfy its path condition. ---> 预测输入，设置优先级。

4. **Savior** integrates fuzzing with symbolic execution. ---> 访问有多分支的路径。

### Problem and challenges

利用轻量级的静态分析去计算中间程序状态，作为执行到目标结果的前提；

精度和速度相违背 ---> tradeoff: ignore path conditions sheerly by focusing on checking a particular property or perform limited reasoning on simple path conditions.

合并路径导致精度缺失，限制路径数量会导致不准确的结果；

## Ⅲ BEACON IN A NUTSHELL

### Backward Interval Analysis

a sound abstraction (or over-approximation)，应用了数值抽象域，但是缺少内部关系( respect inter-variable relations)，导致精度下降；

1. Relationship Preservation

2. Bounded Disjunction

   一定数量的路径到达阙值(exceeds a threshold) ---> merge result

   如何merge，不同的合并方式，导致的误差不同，对精度的影响也不尽相同；

### Selective Instrumentation

instrument two kinds of statements: variable-defining statements and branch statements

添加assert即使终止程序，避免在不可达的路径上浪费时间和算力；

## Ⅳ METHODOLOGY

剔除不可达路径：control flow reachability and path condition satisfiability；

①prune basic blocks that cannot reach the target code by applying a graph reachability analysis on the interprocedural control flow graph (ICFG) of the program. 

②使用高效良好的指针分析去解决函数指针问题，聚焦于专用静态代码测试工具；

**A. preliminary**

Language

Precondition Inference

**B. Backward Interval Analysis**

迭代调用predicate transformers，以考虑所有回溯路径；跟踪所有活动执行的工作列表。

当前的算法在合并路径的时候应用interval abstraction，这样在实际中会降低精度，因此从以下两个角度优化：

1) We design an interval abstraction α that tracks certain inter-variable relations explicitly.

2) We design a bounded disjunction strategy that determines when and how to perform the join operations.

**C. Optimizations for Maintaining Precision**

1. Relationship Preservation

   <img src="C:\Users\Ljfanny\AppData\Roaming\Typora\typora-user-images\image-20220910121240052.png" alt="image-20220910121240052" style="zoom: 50%;" /> 

   conventional interval analyses ---> each statement occurring in the program transforms the interval abstract state

   设计一个top-down的分析器：performs a recursive descent traversal over the path conditions and propagates the known interval values along the way to infer new interval values in a sound manner by respecting laws of interval arithmetic

   与传统分析器不同 ---> track for not only variables but also expressions

   Λ: 表达式到区间的映射

2. Bounded Disjunctions

**D. Precondition Instrumentation**

SSA即静态单赋值，Static Single-Assignment，这是一种中间表示形式。之所以称之为单赋值，是因为每个名字在SSA中仅被赋值一次。

1. We first transform the program into SSA form, and only consider variable definitions as the candidate program locations for instrumentation.
2. When the value of a variable v1 depends only on another variable v2, v1 should not be instrumented. Such information can be computed by the reaching definition data flow analysis.

## Ⅴ EVALUATION

LLVM = **L**ow **L**evel **V**irtual **M**achine

LLVM是构架编译器(compiler)的框架系统，以C++编写而成，用于优化以任意程序语言编写的程序的编译时间(compile-time)、链接时间(link-time)、运行时间(run-time)以及空闲时间(idle-time)，对开发者保持开放，并兼容已有脚本。

1. compared BEACON with four state-of-the-art (directed) fuzzers in the application scenario of vulnerability reproduction

   远比现存directed fuzzers高效，现存non-directed fuzzer应用路径剪枝可以有显著提升；

2. 评估path slicing (slices away infeasible paths based on the reachability on the control flow graph)和precondition checking (prunes infeasible paths according to the precondition analysis)这两种策略对减少fuzzing时间的贡献；

3. 将relationship preservation&bounded disjunction从静态分析中移除，再fuzzing;

4. evaluate the runtime overhead introduced by our instrumentation；

Many existing works are built **based on AFL**, such as AFLGo and Hawkeye. Mopt and AFL++ are also built upon AFL.

**AFLGo and Hawkeye** improve input generation by prioritizing the mutation strategies.

**Mopt and AFL++** integrate with multiple engineer optimizations to improve the overall performance.

## VI. RELATED WORK

Symbolic execution: 静态分析出所有的符号化约束;

Concolic execution: 通过具体执行一遍程序获取该路径相连的边的约束;

## VII. CONCLUSION

We have presented BEACON, which directs the grey-box fuzzer in the sea of paths to avoid unnecessary program execution and, thus, saves a lot of time cost. Compared to existing directed grey-box fuzzers, BEACON can prune infeasible paths provably and more effectively, via the assistance of a dedicated cheap, sound, and precise static analysis. We have provided empirical evidence that BEACON is more effective than the state-of-the-art (directed) fuzzers.