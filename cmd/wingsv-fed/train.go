package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"

	"wingsnet.org/federation/internal/head/boost"
	"wingsnet.org/federation/internal/head/features"
	"wingsnet.org/federation/internal/head/pgstore"
)

// runTrain учит модель на том, что накопила башка.
//
// Отдельной подкомандой, а не по расписанию: обучение это решение оператора, и
// катать свежую модель в бой автоматом, не посмотрев на цифры, значит однажды
// проснуться с половиной флота в карантине
func runTrain(args []string) {
	fs := flag.NewFlagSet("train", flag.ExitOnError)
	dsn := fs.String("dsn", os.Getenv("FED_PG_DSN"), "postgres dsn")
	limit := fs.Int("limit", 200000, "how many labelled rows to take")
	rounds := fs.Int("rounds", 0, "boosting rounds, 0 keeps the default")
	depth := fs.Int("depth", 0, "tree depth, 0 keeps the default")
	minRows := fs.Int("min-rows", 0, "refuse to train on fewer rows")
	live := fs.Bool("live", false, "let the model accuse, not just watch")
	dry := fs.Bool("dry-run", false, "train and report, store nothing")
	_ = fs.Parse(args)

	if *dsn == "" {
		log.Fatal("train: no -dsn and no FED_PG_DSN")
	}
	db, err := pgstore.Open(*dsn)
	if err != nil {
		log.Fatalf("train: database unreachable: %v", err)
	}
	store := pgstore.NewMLStore(db.Gorm())

	samples, err := store.Labelled(features.Version, *limit)
	if err != nil {
		log.Fatalf("train: labelled rows unreadable: %v", err)
	}

	params := boost.DefaultParams()
	if *rounds > 0 {
		params.Rounds = *rounds
	}
	if *depth > 0 {
		params.MaxDepth = *depth
	}
	if *minRows > 0 {
		params.MinTrainRows = *minRows
	}

	positives := 0
	for _, s := range samples {
		if s.Label > 0.5 {
			positives++
		}
	}
	fmt.Printf("rows: %d, of them abusive: %d\n", len(samples), positives)
	// Выборка из одного класса даёт модель, которая всегда отвечает одно и то
	// же, и выглядит это как "точность 100%"
	if positives == 0 || positives == len(samples) {
		log.Fatal("train: one class only, nothing to learn from")
	}

	model, err := boost.Train(features.Names(), samples, params)
	if err != nil {
		log.Fatalf("train: %v", err)
	}

	fmt.Printf("trees: %d, trained on: %d, version: %s\n",
		len(model.Proto().GetTrees()), model.TrainedOn(), model.Version())
	printImportance(model)

	if *dry {
		fmt.Println("dry run, nothing stored")
		return
	}
	if err := store.SaveModel(model, !*live); err != nil {
		log.Fatalf("train: model not stored: %v", err)
	}
	mode := "shadow"
	if *live {
		mode = "live"
	}
	fmt.Printf("stored, mode: %s\n", mode)
}

// printImportance показывает, по чему модель вообще судит. Если наверху окажется
// признак, которого там быть не должно, это видно сразу, а не через месяц
func printImportance(model *boost.Model) {
	importance := model.Importance()
	names := make([]string, 0, len(importance))
	for name := range importance {
		names = append(names, name)
	}
	sort.Slice(names, func(a, b int) bool { return importance[names[a]] > importance[names[b]] })
	fmt.Println("what it judges by:")
	for i, name := range names {
		if i >= 8 {
			break
		}
		fmt.Printf("  %-22s %d\n", name, importance[name])
	}
}
