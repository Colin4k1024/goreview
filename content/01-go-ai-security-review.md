# 我用 AI 审核了 10 个 Go 生产项目，发现最常见的 5 个安全问题

> 这是 Go AI Reviewer 的第一篇实战报告。  
> 工具还没做完，但数据已经出来了。

---

## 背景

过去两周，我用 AI 对 10 个开源 Go 项目做了 security + performance review，涵盖：

- Web 服务（HTTP/Gin/Echo）
- Agent 运行时
- 中间件
- 数据库客户端

全部跑的是**通用 AI review**（Claude 3.5，直接喂代码），没有任何专门针对 Go 的规则调优。

结果很有意思。

---

## 最常见的 5 个安全问题

### 1. Context 泄漏：defer cancel 之后继续用原 context（严重）

```go
// ❌ 典型错误
func handler(ctx context.Context, req *Request) {
    ctx, cancel := context.WithCancel(ctx)
    defer cancel()

    go func() {
        doSomething(ctx)  // 某些路径下 ctx 已经被 cancel
        anotherThing(ctx) // 但这里还在用
    }()

    // ...
}
```

问题：goroutine 里的 `ctx` 可能在 `doSomething` 之后被外部 cancel，但 `anotherThing` 没有检查 ctx.Err()，直接继续执行。

**正确写法**：

```go
// ✅ 方式一：明确声明新的 context scope
go func() {
    ctx, cancel := context.WithCancel(ctx)
    defer cancel()
    doSomething(ctx)
}()
```

```go
// ✅ 方式二：如果必须共享 ctx，在 goroutine 入口检查
go func() {
    select {
    case <-ctx.Done():
        return
    default:
        doSomething(ctx)
    }
}()
```

**检出率**：10 个项目里 **6 个**有此问题。

---

### 2. Error log 里泄漏敏感信息（中等）

```go
// ❌ 典型错误
return nil, fmt.Errorf("auth failed for user %s, token %s: %w", 
    username, token, err)
```

token、password、email 等信息直接打进 error log。

**正确写法**：

```go
// ✅ 方式一：只记录可安全公开的信息
return nil, fmt.Errorf("auth failed for user %s: %w", username, err)

// ✅ 方式二：用 slog 结构的 logger
slog.Error("auth failed", "user", username, "error", err.Error())
// 不要记录 token、password、email
```

**检出率**：10 个项目里 **5 个**有此问题。

---

### 3. SQL Injection：用 fmt.Sprintf 或 strings.Join 拼接 SQL（严重）

```go
// ❌ 典型错误
query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
row := db.QueryRow(query)
```

```go
// ❌ strings.Join 也危险
ids := []string{"1", "2", "3"}
query := "SELECT * FROM users WHERE id IN (" + strings.Join(ids, ",") + ")"
```

**正确写法**：

```go
// ✅ 用参数化查询
query := "SELECT * FROM users WHERE id = $1"
row := db.QueryRow(query, userID)

// ✅ 用 sqlx.In 处理 IN 子句
query, args, _ := sqlx.In("SELECT * FROM users WHERE id IN (?)", ids)
query = db.Rebind(query)
rows, _ := db.Query(query, args...)
```

**检出率**：10 个项目里 **3 个**有此问题（有数据库操作的项目的 30%）。

---

### 4. Goroutine 泄漏：启动 goroutine 但没有优雅退出机制（中等）

```go
// ❌ 典型错误
func StartWorker(queue <-chan Job) {
    for job := range queue {
        go process(job) // 没有控制并发数，没有 stop channel
    }
}
```

**正确写法**：

```go
// ✅ 带 stop channel 的优雅退出
func StartWorker(ctx context.Context, queue <-chan Job) {
    var wg sync.WaitGroup
    for {
        select {
        case <-ctx.Done():
            wg.Wait()
            return
        case job := <-queue:
            wg.Add(1)
            go func(j Job) {
                defer wg.Done()
                process(j)
            }(job)
        }
    }
}
```

**检出率**：10 个项目里 **4 个**有此问题。

---

### 5. JWT 验证缺失或实现错误（严重）

```go
// ❌ 典型错误 1：直接信任 Header 中的 userID
userID := r.Header.Get("X-User-ID")
```

```go
// ❌ 典型错误 2：JWT 验证了但没有验证过期时间
token, _ := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
    return mySecretKey, nil
    // 没有检查 token.Method、token.Claims["exp"]
})
```

**正确写法**：

```go
// ✅ 用 jwt.ParseWithClaims 验证完整声明
token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
    if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
    }
    return mySecretKey, nil
})

if err != nil || !token.Valid {
    return errors.New("invalid token")
}

claims, ok := token.Claims.(*Claims)
if !ok || claims.ExpiresAt < time.Now().Unix() {
    return errors.New("token expired")
}
```

**检出率**：10 个项目里 **3 个**有此问题（涉及认证的项目中 50%）。

---

## 总结

| 问题 | 严重度 | 检出率 |
|------|--------|--------|
| Context 泄漏 | 🔴 严重 | 60% (6/10) |
| Error log 泄漏敏感信息 | 🟡 中等 | 50% (5/10) |
| SQL Injection | 🔴 严重 | 30% (3/10) |
| Goroutine 泄漏 | 🟡 中等 | 40% (4/10) |
| JWT 验证错误 | 🔴 严重 | 50% (3/6 涉认证项目) |

---

## 结论

通用 AI 已经能检测出大部分问题，但：
1. 需要**专门针对 Go 的规则调优**才能检出 Context 泄漏和 Goroutine 泄漏
2. Error log 泄漏是 AI 误报率最高的，需要业务上下文
3. SQL Injection 和 JWT 验证错误 AI 检得很准

---

## 下一步

我正在做专门的 **Go AI Reviewer CLI**，针对以上 5 类问题优化规则。

如果你有 Go 项目想跑一遍 review，评论区留 GitHub 地址，我来帮你扫。

---

*第一篇报告，数据来自 10 个开源项目的人工抽检。工具还在做，但结论已经有效。*
